package smb2_test

// Integration tests for DFS referral following (the feature this fork adds).
//
// They dial their own session from the GOSMB2_DFS_* environment so they can run
// on the same docker network as the lab servers: referral targets are resolved
// by name (e.g. samba-dfs-2:445), which a host-side run reaching a published
// port cannot do. They skip when GOSMB2_DFS_ADDR is unset.
//
// Lab (dev-testing-dfs, run via `docker compose run --rm gosmb2-test`):
//   \\samba-dfs\dfs is an msdfs root with:
//     link1            -> \\samba-dfs\target     (same-server: file1.txt + sub/)
//     xlink            -> \\samba-dfs-2\target2   (cross-server: file2.txt + sub2/)
//     loopa <-> loopb  -> a cyclic link pair      (exercises the depth guard)

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	smb2 "github.com/cloudsoda/go-smb2"
)

// dialDFS dials a session to the lab DFS server and mounts the namespace root by
// UNC name (\\<server>\dfs), so the share path carries the server name the
// referral same-vs-cross detection compares against. Skips if env is not set.
func dialDFS(t *testing.T) (*smb2.Session, *smb2.Share) {
	t.Helper()
	addr := os.Getenv("GOSMB2_DFS_ADDR")
	if addr == "" {
		t.Skip("set GOSMB2_DFS_ADDR (e.g. samba-dfs:445) to run the DFS tests")
	}
	server, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("GOSMB2_DFS_ADDR %q is not host:port: %v", addr, err)
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     os.Getenv("GOSMB2_DFS_USER"),
			Password: os.Getenv("GOSMB2_DFS_PASS"),
			Domain:   os.Getenv("GOSMB2_DFS_DOMAIN"),
		},
	}
	s, err := d.Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("Dial(%s): %v", addr, err)
	}
	// Mount by UNC name (not the bare share) so the share path is \\server\dfs and
	// the referral detection has a server name to compare the target against.
	dfs, err := s.Mount(`\\` + server + `\dfs`)
	if err != nil {
		_ = s.Logoff()
		t.Fatalf(`Mount(\\%s\dfs): %v`, server, err)
	}
	return s, dfs
}

// TestDFSReferralFollowing verifies that reading a same-server DFS link
// transparently follows the referral and returns the target's contents, instead
// of failing with STATUS_PATH_NOT_COVERED.
func TestDFSReferralFollowing(t *testing.T) {
	s, dfs := dialDFS(t)
	defer func() { _ = dfs.Umount(); _ = s.Logoff() }()

	entries, err := dfs.ReadDir("link1")
	if err != nil {
		t.Fatalf(`ReadDir("link1") should follow the DFS referral, got: %v`, err)
	}
	assertHasFileAndDir(t, entries, "file1.txt", "sub")
}

// TestDFSReferralCrossServer verifies that a referral whose target lives on a
// different server is followed by dialing that server fresh — not by reusing the
// current session, which would wrongly serve the local share of the same name.
func TestDFSReferralCrossServer(t *testing.T) {
	s, dfs := dialDFS(t)
	defer func() { _ = dfs.Umount(); _ = s.Logoff() }()

	entries, err := dfs.ReadDir("xlink")
	if err != nil {
		t.Fatalf(`ReadDir("xlink") should follow the cross-server referral, got: %v`, err)
	}
	assertHasFileAndDir(t, entries, "file2.txt", "sub2")
}

// TestDFSReferralLoopGuard verifies that a cyclic DFS namespace
// (loopa -> loopb -> loopa) is bounded by the referral depth guard instead of
// recursing forever.
func TestDFSReferralLoopGuard(t *testing.T) {
	s, dfs := dialDFS(t)
	defer func() { _ = dfs.Umount(); _ = s.Logoff() }()

	_, err := dfs.ReadDir("loopa")
	if err == nil {
		t.Fatal("expected an error from the cyclic DFS link, got nil")
	}
	if !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected the depth-guard error, got: %v", err)
	}
}

// assertHasFileAndDir asserts the listing contains a regular file and a directory
// with the given names (the shape every lab target share is seeded with).
func assertHasFileAndDir(t *testing.T, entries []os.FileInfo, file, dir string) {
	t.Helper()
	if len(entries) == 0 {
		t.Fatal("followed the referral but the target listing was empty")
	}
	isDir := make(map[string]bool, len(entries))
	for _, e := range entries {
		isDir[e.Name()] = e.IsDir()
	}
	if d, ok := isDir[file]; !ok || d {
		t.Errorf("expected file %q in the target, got: %v", file, isDir)
	}
	if d, ok := isDir[dir]; !ok || !d {
		t.Errorf("expected directory %q in the target, got: %v", dir, isDir)
	}
}
