/*
Copyright 2026 Cloudaura sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policy

import "testing"

func TestGlobMatcher_ExactLiteralMatch(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/bar"}
	if !g.Match("foo/bar") {
		t.Error("expected pattern \"foo/bar\" to match path \"foo/bar\"")
	}
}

func TestGlobMatcher_ExactLiteralMismatch(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/bar"}
	if g.Match("foo/baz") {
		t.Error("expected pattern \"foo/bar\" NOT to match path \"foo/baz\"")
	}
}

func TestGlobMatcher_SingleStar_MatchesNonSeparator(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/*.txt"}
	if !g.Match("foo/bar.txt") {
		t.Error("expected pattern \"foo/*.txt\" to match \"foo/bar.txt\"")
	}
}

func TestGlobMatcher_SingleStar_DoesNotCrossSeparator(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/*"}
	if g.Match("foo/bar/baz") {
		t.Error("expected pattern \"foo/*\" NOT to match \"foo/bar/baz\"")
	}
}

func TestGlobMatcher_SingleStar_MatchesEmptySegment(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/*bar"}
	if !g.Match("foo/bar") {
		t.Error("expected pattern \"foo/*bar\" to match \"foo/bar\" (star matches empty)")
	}
}

func TestGlobMatcher_DoubleStar_AtEnd_MatchesEverythingRecursively(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/**"}
	if !g.Match("foo/bar/baz/qux") {
		t.Error("expected pattern \"foo/**\" to match \"foo/bar/baz/qux\"")
	}
}

func TestGlobMatcher_DoubleStar_InMiddle_MatchesZeroSegments(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/**/bar"}
	if !g.Match("foo/bar") {
		t.Error("expected pattern \"foo/**/bar\" to match \"foo/bar\" (zero intermediate segments)")
	}
}

func TestGlobMatcher_DoubleStar_InMiddle_MatchesMultipleSegments(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo/**/bar"}
	if !g.Match("foo/a/b/c/bar") {
		t.Error("expected pattern \"foo/**/bar\" to match \"foo/a/b/c/bar\"")
	}
}

func TestGlobMatcher_QuestionMark_MatchesSingleChar(t *testing.T) {
	g := &GlobMatcher{Pattern: "fo?"}
	if !g.Match("foo") {
		t.Error("expected pattern \"fo?\" to match \"foo\"")
	}
}

func TestGlobMatcher_QuestionMark_DoesNotMatchSlash(t *testing.T) {
	g := &GlobMatcher{Pattern: "fo?"}
	if g.Match("fo/") {
		t.Error("expected pattern \"fo?\" NOT to match \"fo/\"")
	}
}

func TestGlobMatcher_QuestionMark_DoesNotMatchEmpty(t *testing.T) {
	g := &GlobMatcher{Pattern: "fo?"}
	if g.Match("fo") {
		t.Error("expected pattern \"fo?\" NOT to match \"fo\"")
	}
}

func TestGlobMatcher_EmptyPatternMatchesEmptyPath(t *testing.T) {
	g := &GlobMatcher{Pattern: ""}
	if !g.Match("") {
		t.Error("expected empty pattern to match empty path")
	}
}

func TestGlobMatcher_EmptyPatternDoesNotMatchNonEmpty(t *testing.T) {
	g := &GlobMatcher{Pattern: ""}
	if g.Match("foo") {
		t.Error("expected empty pattern NOT to match non-empty path \"foo\"")
	}
}

func TestGlobMatcher_NonEmptyPatternDoesNotMatchEmpty(t *testing.T) {
	g := &GlobMatcher{Pattern: "foo"}
	if g.Match("") {
		t.Error("expected non-empty pattern \"foo\" NOT to match empty path")
	}
}

func TestGlobMatcher_NoMatch_UnrelatedPatternAndPath(t *testing.T) {
	g := &GlobMatcher{Pattern: "abc/def"}
	if g.Match("xyz/123") {
		t.Error("expected pattern \"abc/def\" NOT to match \"xyz/123\"")
	}
}

func TestGlobMatcher_ComplexCombined_DoubleStarAndStar(t *testing.T) {
	g := &GlobMatcher{Pattern: "**/foo/*.go"}
	if !g.Match("a/b/foo/main.go") {
		t.Error("expected pattern \"**/foo/*.go\" to match \"a/b/foo/main.go\"")
	}
}

func TestGlobMatcher_ComplexCombined_QuestionMarkAndStar(t *testing.T) {
	g := &GlobMatcher{Pattern: "f?o/*.txt"}
	if !g.Match("foo/bar.txt") {
		t.Error("expected pattern \"f?o/*.txt\" to match \"foo/bar.txt\"")
	}
	if g.Match("fooo/bar.txt") {
		t.Error("expected pattern \"f?o/*.txt\" NOT to match \"fooo/bar.txt\"")
	}
}
