package smb2

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// dfsReferralCache caches resolved DFS referrals per connection, honoring the
// per-referral TTL so a hot link does not trigger a lookup on every access.
type dfsReferralCache struct {
	mu      sync.Mutex
	entries map[string]dfsCacheEntry
}

type dfsCacheEntry struct {
	target       string // referral NetworkAddress (`\server\share[\sub]`)
	pathConsumed uint16
	expiresAt    time.Time
}

func newDfsReferralCache() *dfsReferralCache {
	return &dfsReferralCache{entries: make(map[string]dfsCacheEntry)}
}

// get returns a non-expired entry for key (DFS paths are case-insensitive, so
// keys are lowercased by the caller). Expired entries are evicted on access.
func (c *dfsReferralCache) get(key string) (dfsCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return dfsCacheEntry{}, false
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return dfsCacheEntry{}, false
	}
	return e, true
}

func (c *dfsReferralCache) put(key string, e dfsCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = e
}

// dfsReferralCache lazily creates and returns the connection's referral cache.
func (conn *conn) dfsReferralCache() *dfsReferralCache {
	conn.dfsCacheOnce.Do(func() {
		conn.dfsCache = newDfsReferralCache()
	})
	return conn.dfsCache
}

const (
	// dfsReferralMaxLevel is the highest DFS referral version we request.
	dfsReferralMaxLevel = 4
	// dfsReferralMaxOutput bounds the IOCTL output buffer for the response.
	dfsReferralMaxOutput = 64 * 1024
	// maxDfsReferralDepth bounds how many chained referrals we follow before
	// giving up, to avoid looping forever on a misconfigured (cyclic) namespace.
	maxDfsReferralDepth = 8
)

// dfsNoFileID is the all-0xFF file id used for FSCTL_DFS_GET_REFERRALS, which is
// issued on a tree without an open file handle (MS-SMB2 3.2.4.20.3).
var dfsNoFileID = [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// getDfsReferral resolves a DFS path against its namespace server by issuing
// FSCTL_DFS_GET_REFERRALS on the server's IPC$ tree. dfsPath is the full DFS
// path that triggered STATUS_PATH_NOT_COVERED (e.g. `\server\namespace\link`).
//
// It reuses the existing connection: the IPC$ tree connect rides the same
// session, so no new dial/DNS lookup is needed to fetch the referral.
//
// It returns PathConsumed (bytes of dfsPath the server resolved) alongside the
// referral entries, so the caller can stitch the unconsumed remainder onto the
// target.
func (fs *Share) getDfsReferral(dfsPath string) (uint16, []smb2.DfsReferral, error) {
	server, err := dfsServerOf(fs.path)
	if err != nil {
		return 0, nil, err
	}

	ipcTc, err := treeConnect(fs.ctx, fs.session, fmt.Sprintf(`\\%s\IPC$`, server), 0, fs.mapping)
	if err != nil {
		return 0, nil, fmt.Errorf("DFS: tree connect to IPC$ failed: %w", err)
	}
	ipc := &Share{treeConn: ipcTc, ctx: fs.ctx, mapping: fs.mapping}
	defer func() { _ = ipc.Umount() }()

	input := &smb2.ReqGetDfsReferral{
		MaxReferralLevel: dfsReferralMaxLevel,
		RequestFileName:  dfsPath,
	}

	req := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_DFS_GET_REFERRALS,
		FileId:            &smb2.FileId{Persistent: dfsNoFileID, Volatile: dfsNoFileID},
		MaxOutputResponse: dfsReferralMaxOutput,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input:             input,
	}

	req.CreditCharge, _, err = ipc.loanCredit(input.Size() + dfsReferralMaxOutput)
	if err != nil {
		return 0, nil, err
	}

	res, err := ipc.sendRecv(smb2.SMB2_IOCTL, req)
	if err != nil {
		return 0, nil, fmt.Errorf("DFS: FSCTL_DFS_GET_REFERRALS failed: %w", err)
	}

	ir := smb2.IoctlResponseDecoder(res)
	if ir.IsInvalid() {
		return 0, nil, &InvalidResponseError{"broken ioctl response format"}
	}

	dec := smb2.RespGetDfsReferralDecoder(ir.Output())
	refs := dec.Referrals()
	if len(refs) == 0 {
		return 0, nil, &InternalError{"DFS referral response had no entries"}
	}
	return dec.PathConsumed(), refs, nil
}

// dfsRequestPath builds the DFS RequestFileName for a create whose share-relative
// name triggered STATUS_PATH_NOT_COVERED, e.g. share `\\srv\dfs` + name `link1`
// -> `\srv\dfs\link1` (single leading backslash, no trailing one).
func (fs *Share) dfsRequestPath(name string) string {
	base := strings.Trim(fs.path, `\`)
	name = strings.Trim(name, `\`)
	if name == "" {
		return `\` + base
	}
	return `\` + base + `\` + name
}

// dfsServerOf extracts the server from a `\\server\share[\...]` UNC path.
func dfsServerOf(uncPath string) (string, error) {
	p := strings.TrimLeft(uncPath, `\`)
	i := strings.IndexByte(p, '\\')
	if i <= 0 {
		return "", &InternalError{"cannot determine DFS server from path: " + uncPath}
	}
	return p[:i], nil
}

// followDfsReferral resolves the DFS referral for a create that hit
// STATUS_PATH_NOT_COVERED and returns a File opened on the referral target.
//
// It reuses the current session for the target tree connect, which works when
// the target lives on the same server we are already connected to (the common
// intra-server link case, and our test lab). Cross-server targets would need a
// fresh dial — TODO.
func (fs *Share) followDfsReferral(name string, req *smb2.CreateRequest) (*File, error) {
	if fs.dfsDepth >= maxDfsReferralDepth {
		return nil, &InternalError{"DFS: too many chained referrals (possible namespace loop)"}
	}

	reqPath := fs.dfsRequestPath(name)
	key := strings.ToLower(reqPath) // DFS paths are case-insensitive
	cache := fs.session.conn.dfsReferralCache()

	var target string
	var pathConsumed uint16
	if e, ok := cache.get(key); ok {
		target, pathConsumed = e.target, e.pathConsumed
	} else {
		pc, refs, rerr := fs.getDfsReferral(reqPath)
		if rerr != nil {
			return nil, rerr
		}
		target, pathConsumed = refs[0].NetworkAddress, pc
		ttl := time.Duration(refs[0].TimeToLive) * time.Second
		cache.put(key, dfsCacheEntry{target: target, pathConsumed: pathConsumed, expiresAt: time.Now().Add(ttl)})
	}
	if target == "" {
		return nil, &InternalError{"DFS referral had empty target"}
	}

	server, share, sub, err := splitTargetUNC(target)
	if err != nil {
		return nil, err
	}

	// Append the unconsumed remainder of the original request to the target.
	rel := joinDfs(sub, dfsRemainder(reqPath, pathConsumed))

	tc, err := treeConnect(fs.ctx, fs.session, fmt.Sprintf(`\\%s\%s`, server, share), 0, fs.mapping)
	if err != nil {
		return nil, fmt.Errorf("DFS: tree connect to target %q failed: %w", target, err)
	}
	targetShare := &Share{treeConn: tc, ctx: fs.ctx, mapping: fs.mapping, dfsDepth: fs.dfsDepth + 1}

	// Recurse so a chained referral on the target resolves too (bounded by dfsDepth).
	return targetShare.createFile(normPath(rel), req, true)
}

// dfsRemainder returns the part of reqPath not consumed by the referral.
// pathConsumed is in bytes of the UTF-16 request name; for BMP paths that is
// 2 bytes per character.
func dfsRemainder(reqPath string, pathConsumed uint16) string {
	chars := int(pathConsumed) / 2
	r := []rune(reqPath)
	if chars >= len(r) {
		return ""
	}
	return string(r[chars:])
}

// splitTargetUNC splits `\server\share[\sub\path]` into its parts.
func splitTargetUNC(target string) (server, share, sub string, err error) {
	p := strings.TrimLeft(target, `\`)
	parts := strings.SplitN(p, `\`, 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", &InternalError{"malformed DFS target: " + target}
	}
	server, share = parts[0], parts[1]
	if len(parts) == 3 {
		sub = parts[2]
	}
	return server, share, sub, nil
}

// joinDfs joins two backslash path fragments, tolerating empties.
func joinDfs(a, b string) string {
	a = strings.Trim(a, `\`)
	b = strings.Trim(b, `\`)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + `\` + b
	}
}
