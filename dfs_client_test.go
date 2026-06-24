package smb2

import (
	"testing"
	"time"
)

func TestDfsReferralCache(t *testing.T) {
	c := newDfsReferralCache()

	if _, ok := c.get(`\srv\dfs\link`); ok {
		t.Fatal("expected miss on empty cache")
	}

	// Live entry -> hit.
	c.put(`\srv\dfs\link`, dfsCacheEntry{
		target:       `\srv\target`,
		pathConsumed: 20,
		expiresAt:    time.Now().Add(time.Minute),
	})
	e, ok := c.get(`\srv\dfs\link`)
	if !ok {
		t.Fatal("expected hit for live entry")
	}
	if e.target != `\srv\target` || e.pathConsumed != 20 {
		t.Fatalf("unexpected entry: %+v", e)
	}

	// Expired entry -> miss (and evicted).
	c.put(`\srv\dfs\old`, dfsCacheEntry{
		target:    `\srv\target`,
		expiresAt: time.Now().Add(-time.Second),
	})
	if _, ok := c.get(`\srv\dfs\old`); ok {
		t.Fatal("expected miss on expired entry")
	}
}

func TestDfsPathHelpers(t *testing.T) {
	// dfsRemainder: pathConsumed is in bytes (2 per BMP char).
	if got := dfsRemainder(`\a\b\c`, 8); got != `\c` { // 8 bytes = 4 chars consumed (`\a\b`)
		t.Errorf("dfsRemainder consumed-prefix = %q, want %q", got, `\c`)
	}
	if got := dfsRemainder(`\a\b\c`, 12); got != "" { // whole path consumed
		t.Errorf("dfsRemainder full = %q, want empty", got)
	}

	// splitTargetUNC.
	srv, sh, sub, err := splitTargetUNC(`\server\share\a\b`)
	if err != nil || srv != "server" || sh != "share" || sub != `a\b` {
		t.Errorf("splitTargetUNC = (%q,%q,%q,%v)", srv, sh, sub, err)
	}
	srv, sh, sub, err = splitTargetUNC(`\server\share`)
	if err != nil || srv != "server" || sh != "share" || sub != "" {
		t.Errorf("splitTargetUNC no-sub = (%q,%q,%q,%v)", srv, sh, sub, err)
	}
	if _, _, _, err := splitTargetUNC(`\server`); err == nil {
		t.Error("splitTargetUNC should fail on missing share")
	}

	// joinDfs.
	for _, tc := range []struct{ a, b, want string }{
		{"", "x", "x"},
		{"a", "", "a"},
		{"a", "b", `a\b`},
		{`\a\`, `\b\`, `a\b`},
	} {
		if got := joinDfs(tc.a, tc.b); got != tc.want {
			t.Errorf("joinDfs(%q,%q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}
