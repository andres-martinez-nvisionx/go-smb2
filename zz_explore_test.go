package smb2_test

// Exploratory tests for the CIFS DFS spike. They reuse the smb2_test.go harness
// (TestMain + the global `fs`/`session`, mounted per client_conf.json) and skip
// when there is no server configured. They exercise ReadDirPlus (batched
// traversal + ACL), NTLM auth, the Kerberos entry point, and the DFS
// referral-following added in this fork.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
)

func TestExploreReadDirPlus(t *testing.T) {
	if fs == nil {
		t.Skip("no client_conf.json / server")
	}

	flags := smb2.OwnerSecurityInformation |
		smb2.GroupSecurityInformation |
		smb2.DACLSecurityInformation

	dir := "dir_1_00" // subdir of the seeded tree (16 files + 5 subdirs)

	start := time.Now()
	entries, err := fs.ReadDirPlus(dir, flags)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ReadDirPlus(%q): %v", dir, err)
	}

	t.Logf("ReadDirPlus(%q): %d entries in %s (traversal + ACL, batched)",
		dir, len(entries), elapsed)
	for _, e := range entries {
		sd := "<nil>"
		if e.SecurityDescriptor != nil {
			sd = e.SecurityDescriptor.String()
		}
		if e.Err != nil {
			sd = "ERR: " + e.Err.Error()
		}
		t.Logf("  %-20s dir=%-5v  SD=%s", e.Name(), e.IsDir(), sd)
	}
}

// TestExploreNTLMAuth confirms the auth is real NTLM: a bad password must FAIL.
// If a bad password "worked", we'd be falling back to guest/anonymous and not
// exercising NTLM at all.
func TestExploreNTLMAuth(t *testing.T) {
	const addr = "127.0.0.1:14450"

	// 1) bad password -> must fail.
	bad := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{
		User: "testuser", Password: "WRONG-PASSWORD", Domain: "WORKGROUP",
	}}
	if c, err := bad.Dial(context.Background(), addr); err == nil {
		_ = c.Logoff()
		t.Fatal("bad password was accepted -> not real NTLM (guest/anonymous?)")
	} else {
		t.Logf("bad password rejected (expected): %v", err)
	}

	// 2) good password -> must work (positive control).
	good := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{
		User: "testuser", Password: "testpass", Domain: "WORKGROUP",
	}}
	c, err := good.Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("good password rejected (unexpected): %v", err)
	}
	defer func() { _ = c.Logoff() }()
	t.Log("good password accepted -> NTLM auth confirmed end-to-end")
}

// TestExploreKerberosShape shows the Kerberos path EXISTS in go-smb2 but needs
// infra (KDC/realm/SPN) the samba-dfs lab doesn't have. It mounts nothing: it
// just exercises the entry point with an initiator that has no Client and checks
// that the guard fires.
func TestExploreKerberosShape(t *testing.T) {
	// A Krb5Initiator needs: .Client (gokrb5, built from /etc/krb5.conf + a login
	// against the KDC) and .TargetSPN (e.g. "cifs/samba-dfs@REALM"). Without those:
	ki := &smb2.Krb5Initiator{TargetSPN: "cifs/samba-dfs"} // Client = nil on purpose
	_, err := ki.InitSecContext()
	if err == nil {
		t.Fatal("expected failure without a Client/KDC")
	}
	t.Logf("Kerberos without infra fails (expected): %v", err)
	t.Log("to test it for real: KDC + krb5.conf + SPN + synced clocks (not our lab)")
}

// TestExploreDFSReferral mounts the DFS namespace, lists the root (where link1
// shows up as a reparse point) and descends into the link. With referral-
// following in place, descending transparently returns the target share's
// contents instead of STATUS_PATH_NOT_COVERED.
func TestExploreDFSReferral(t *testing.T) {
	if session == nil {
		t.Skip("no session/server")
	}

	dfsShare, err := session.Mount("dfs")
	if err != nil {
		t.Fatalf("Mount(dfs): %v", err)
	}
	defer func() { _ = dfsShare.Umount() }()

	// 1) Namespace root: link1 should show up (as a reparse point).
	root, err := dfsShare.ReadDir(".")
	if err != nil {
		t.Logf("ReadDir(root) err: %v", err)
	} else {
		for _, e := range root {
			t.Logf("  root: %-10s dir=%v", e.Name(), e.IsDir())
		}
	}

	// 2) Descend into the link -> follows the DFS referral and lists the target.
	entries, err := dfsShare.ReadDir("link1")
	t.Logf("ReadDir(\"link1\") -> %d entries, err=%v", len(entries), err)
	if err != nil {
		t.Logf("*** error to intercept for referral-following ***")
		return
	}
	for _, e := range entries {
		t.Logf("  target: %-12s dir=%v size=%d", e.Name(), e.IsDir(), e.Size())
	}
}

// TestExploreBatchVsPerFile contrasts the two ways to fetch ACLs for a directory
// at the CURRENT netem setting: per-file SecurityInfo (open+query+close ≈ 3 RTT
// each) vs ReadDirPlus (traversal + ACL compounded/sub-batched by credits). Both
// are go-smb2, single-threaded — so the gap is purely the round-trip reduction.
func TestExploreBatchVsPerFile(t *testing.T) {
	if fs == nil {
		t.Skip("no client_conf.json / server")
	}
	const dir = "dir_1_00"
	flags := smb2.OwnerSecurityInformation |
		smb2.GroupSecurityInformation |
		smb2.DACLSecurityInformation

	entries, err := fs.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}

	// A) per-file: one SecurityInfo (open+query+close) per entry.
	startA := time.Now()
	for _, e := range entries {
		if _, err := fs.SecurityInfo(dir+`\`+e.Name(), flags); err != nil {
			t.Fatalf("SecurityInfo(%s): %v", e.Name(), err)
		}
	}
	perFile := time.Since(startA)

	// B) batched: one ReadDirPlus for the whole directory.
	startB := time.Now()
	plus, err := fs.ReadDirPlus(dir, flags)
	if err != nil {
		t.Fatalf("ReadDirPlus(%q): %v", dir, err)
	}
	batched := time.Since(startB)

	t.Logf("RESULT entries=%d perFile=%s batched=%s ratio=%.1fx",
		len(plus), perFile.Round(time.Millisecond), batched.Round(time.Millisecond),
		float64(perFile)/float64(batched))
}

// TestExploreDFSLoopGuard checks the chained-referral depth guard: the lab has
// cyclic links loopa -> loopb -> loopa, so following must bail out instead of
// looping forever.
func TestExploreDFSLoopGuard(t *testing.T) {
	if session == nil {
		t.Skip("no session/server")
	}
	dfsShare, err := session.Mount("dfs")
	if err != nil {
		t.Fatalf("Mount(dfs): %v", err)
	}
	defer func() { _ = dfsShare.Umount() }()

	_, err = dfsShare.ReadDir("loopa")
	if err == nil {
		t.Fatal("expected an error from the cyclic DFS link, got nil")
	}
	t.Logf("loopa -> %v", err)
	if !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected the depth-guard error, got: %v", err)
	}
}
