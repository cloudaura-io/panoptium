package k8s

import "testing"

func TestIndexOfMatches(t *testing.T) {
	cases := map[string]struct {
		haystack, needle string
		want             int
	}{
		"front":   {"hello world", "hello", 0},
		"middle":  {"hello world", "lo w", 3},
		"tail":    {"hello world", "world", 6},
		"missing": {"hello world", "xyz", -1},
		"empty":   {"hello", "", 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := indexOf(tc.haystack, tc.needle)
			if got != tc.want {
				t.Errorf("indexOf(%q, %q) = %d, want %d", tc.haystack, tc.needle, got, tc.want)
			}
		})
	}
}

func TestContainsEmptyOrMismatched(t *testing.T) {
	if contains("x", "") {
		t.Error("contains should return false for empty needle")
	}
	if contains("short", "longer") {
		t.Error("contains should return false when haystack shorter than needle")
	}
	if !contains("abcdef", "cd") {
		t.Error("contains failed for matching middle")
	}
}
