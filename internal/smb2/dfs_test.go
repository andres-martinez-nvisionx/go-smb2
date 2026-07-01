package smb2

import (
	"testing"
	"unicode/utf16"
)

// encU16z encodes s as null-terminated UTF-16LE (test helper).
func encU16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2+2)
	for i, c := range u {
		le.PutUint16(b[2*i:], c)
	}
	return b // trailing 2 bytes are the zero terminator
}

func TestReqGetDfsReferralEncode(t *testing.T) {
	req := &ReqGetDfsReferral{MaxReferralLevel: 4, RequestFileName: `\samba-dfs\dfs\link1`}

	b := make([]byte, req.Size())
	req.Encode(b)

	if got := le.Uint16(b[0:2]); got != 4 {
		t.Fatalf("MaxReferralLevel = %d, want 4", got)
	}
	if got := le.Uint16(b[len(b)-2:]); got != 0 {
		t.Fatalf("missing null terminator, got %#x", got)
	}
	if got := dfsDecodeUTF16z(b[2:]); got != req.RequestFileName {
		t.Fatalf("filename round-trip = %q, want %q", got, req.RequestFileName)
	}
}

func TestRespGetDfsReferralDecodeV4(t *testing.T) {
	const dfsPath = `\samba-dfs\dfs\link1`
	const target = `\samba-dfs\target`

	dfsPathB := encU16z(dfsPath)
	targetB := encU16z(target)

	// V4 entry: 34-byte fixed header (incl. 16-byte ServiceSiteGuid), then strings.
	dfsPathOff := 34
	netAddrOff := dfsPathOff + len(dfsPathB)
	size := netAddrOff + len(targetB)

	entry := make([]byte, size)
	le.PutUint16(entry[0:2], 4)             // VersionNumber
	le.PutUint16(entry[2:4], uint16(size))  // Size
	le.PutUint16(entry[4:6], 0)             // ServerType
	le.PutUint16(entry[6:8], 0)             // ReferralEntryFlags (normal, not name-list)
	le.PutUint32(entry[8:12], 300)          // TimeToLive
	le.PutUint16(entry[12:14], uint16(dfsPathOff))
	le.PutUint16(entry[14:16], uint16(dfsPathOff)) // DFSAlternatePathOffset (unused here)
	le.PutUint16(entry[16:18], uint16(netAddrOff))
	// entry[18:34] = ServiceSiteGuid, left zero
	copy(entry[dfsPathOff:], dfsPathB)
	copy(entry[netAddrOff:], targetB)

	resp := make([]byte, 8)
	le.PutUint16(resp[0:2], 2)  // PathConsumed (arbitrary)
	le.PutUint16(resp[2:4], 1)  // NumberOfReferrals
	le.PutUint32(resp[4:8], 0)  // ReferralHeaderFlags
	resp = append(resp, entry...)

	d := RespGetDfsReferralDecoder(resp)
	if d.IsInvalid() {
		t.Fatal("decoder reports invalid for a well-formed response")
	}
	if got := d.NumberOfReferrals(); got != 1 {
		t.Fatalf("NumberOfReferrals = %d, want 1", got)
	}

	refs := d.Referrals()
	if len(refs) != 1 {
		t.Fatalf("got %d referrals, want 1", len(refs))
	}
	r := refs[0]
	if r.VersionNumber != 4 {
		t.Errorf("VersionNumber = %d, want 4", r.VersionNumber)
	}
	if r.TimeToLive != 300 {
		t.Errorf("TimeToLive = %d, want 300", r.TimeToLive)
	}
	if r.DFSPath != dfsPath {
		t.Errorf("DFSPath = %q, want %q", r.DFSPath, dfsPath)
	}
	if r.NetworkAddress != target {
		t.Errorf("NetworkAddress = %q, want %q", r.NetworkAddress, target)
	}
}

// TestRespGetDfsReferralNameList decodes a V4 name-list (domain/DC) referral —
// the domain-based DFS bootstrap entry that carries a list of DC / root-target
// servers instead of a single NetworkAddress. Synthetic bytes (no AD needed);
// swap them for a real SSB capture when available to raise fidelity.
func TestRespGetDfsReferralNameList(t *testing.T) {
	const special = `\CORP`
	names := []string{`\dc1.corp.acme.com`, `\dc2.corp.acme.com`}

	// Name-list V3/V4 fixed header is 18 bytes (no ServiceSiteGuid); strings follow.
	const fixed = 18
	specialB := encU16z(special)
	var namesB []byte
	for _, n := range names {
		namesB = append(namesB, encU16z(n)...)
	}

	specialOff := fixed
	expandedOff := specialOff + len(specialB)

	entry := make([]byte, fixed)
	le.PutUint16(entry[0:2], 4)                        // VersionNumber
	le.PutUint16(entry[2:4], fixed)                    // Size (fixed part; strings are shared, after)
	le.PutUint16(entry[4:6], 0)                        // ServerType
	le.PutUint16(entry[6:8], 0x0002)                   // ReferralEntryFlags = name-list
	le.PutUint32(entry[8:12], 600)                     // TimeToLive
	le.PutUint16(entry[12:14], uint16(specialOff))     // SpecialNameOffset
	le.PutUint16(entry[14:16], uint16(len(names)))     // NumberOfExpandedNames
	le.PutUint16(entry[16:18], uint16(expandedOff))    // ExpandedNameOffset
	entry = append(entry, specialB...)
	entry = append(entry, namesB...)

	resp := make([]byte, 8)
	le.PutUint16(resp[2:4], 1) // NumberOfReferrals
	resp = append(resp, entry...)

	refs := RespGetDfsReferralDecoder(resp).Referrals()
	if len(refs) != 1 {
		t.Fatalf("got %d referrals, want 1", len(refs))
	}
	r := refs[0]
	if !r.IsNameList() {
		t.Fatal("IsNameList() = false, want true for a name-list referral")
	}
	if r.SpecialName != special {
		t.Errorf("SpecialName = %q, want %q", r.SpecialName, special)
	}
	if len(r.ExpandedNames) != 2 || r.ExpandedNames[0] != names[0] || r.ExpandedNames[1] != names[1] {
		t.Errorf("ExpandedNames = %v, want %v", r.ExpandedNames, names)
	}
	if r.NetworkAddress != "" {
		t.Errorf("NetworkAddress = %q, want empty for a name-list referral", r.NetworkAddress)
	}
}
