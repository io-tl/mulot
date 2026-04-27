package navigation

import "testing"

func TestSkipReason(t *testing.T) {
	current := "http://localhost/security.php"
	cases := []struct {
		url      string
		wantSkip bool
	}{
		{"http://localhost/security.php#", true},          // same-page anchor
		{"#top", true},                                    // bare fragment
		{"http://localhost/logout.php", true},             // logout
		{"http://localhost/users/42/delete", true},        // delete
		{"http://localhost/account?action=logout", true},  // action=logout
		{"http://localhost/setup.php", true},              // reset DB page
		{"http://localhost/index.php", false},             // normal link
		{"http://localhost/vulnerabilities/sqli/", false}, // normal link
	}
	for _, c := range cases {
		got := skipReason(c.url, current) != ""
		if got != c.wantSkip {
			t.Errorf("skipReason(%q) skip=%v, want %v", c.url, got, c.wantSkip)
		}
	}
}

func TestGetBrokenLinksExcludesSkipped(t *testing.T) {
	results := []LinkCheckResult{
		{URL: "a", Status: 200},
		{URL: "b", Status: 404, Broken: true},
		{URL: "c", Status: 0, Broken: true, Skipped: true, SkipReason: "same-page anchor"},
	}
	broken := GetBrokenLinks(results)
	if len(broken) != 1 || broken[0].URL != "b" {
		t.Errorf("expected only 'b' broken, got %+v", broken)
	}
}
