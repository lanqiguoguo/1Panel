package service

import (
	"strings"
	"testing"
)

// TestSetPHPLimitLinesBothPresent verifies the common case: a php.ini that
// already carries both directives has both lines rewritten to the new value.
func TestSetPHPLimitLinesBothPresent(t *testing.T) {
	ini := "post_max_size = 8M\nupload_max_filesize = 2M\nmemory_limit = 128M"
	lines := setPHPLimitLines(strings.Split(ini, "\n"), "100M")
	got := strings.Join(lines, "\n")
	want := "post_max_size = 100M\nupload_max_filesize = 100M\nmemory_limit = 128M"
	if got != want {
		t.Errorf("setPHPLimitLines both-present mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestSetPHPLimitLinesMissingUpload verifies the reported bug: when the file
// has post_max_size but no upload_max_filesize line, the missing directive
// must be appended; previously only post_max_size was updated and PHP's
// compiled-in upload default silently stayed in effect.
func TestSetPHPLimitLinesMissingUpload(t *testing.T) {
	ini := "post_max_size = 8M"
	lines := setPHPLimitLines(strings.Split(ini, "\n"), "100M")
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "post_max_size = 100M") {
		t.Errorf("post_max_size not replaced, got %q", got)
	}
	if !strings.Contains(got, "upload_max_filesize = 100M") {
		t.Errorf("upload_max_filesize not appended, got %q", got)
	}
	if strings.Count(got, "upload_max_filesize = 100M") != 1 {
		t.Errorf("upload_max_filesize appended more than once, got %q", got)
	}
}

// TestSetPHPLimitLinesMissingPost verifies the mirrored case: a file with
// only upload_max_filesize gets post_max_size appended.
func TestSetPHPLimitLinesMissingPost(t *testing.T) {
	ini := "upload_max_filesize = 2M"
	lines := setPHPLimitLines(strings.Split(ini, "\n"), "100M")
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "upload_max_filesize = 100M") {
		t.Errorf("upload_max_filesize not replaced, got %q", got)
	}
	if !strings.Contains(got, "post_max_size = 100M") {
		t.Errorf("post_max_size not appended, got %q", got)
	}
	if strings.Count(got, "post_max_size = 100M") != 1 {
		t.Errorf("post_max_size appended more than once, got %q", got)
	}
}

// TestSetPHPLimitLinesCommentsUntouched verifies that commented-out keys
// (lines starting with ';') are never treated as active directives.
func TestSetPHPLimitLinesCommentsUntouched(t *testing.T) {
	ini := ";upload_max_filesize = 2M\npost_max_size = 8M"
	lines := setPHPLimitLines(strings.Split(ini, "\n"), "100M")
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, ";upload_max_filesize = 2M") {
		t.Errorf("commented directive was modified, got %q", got)
	}
	if strings.Count(got, "upload_max_filesize = 100M") != 1 {
		t.Errorf("active upload_max_filesize not appended once, got %q", got)
	}
	if !strings.Contains(got, "post_max_size = 100M") {
		t.Errorf("post_max_size not replaced, got %q", got)
	}
}

// TestSetPHPLimitLinesKeyIndependence is the "no cross-overwrite" pin: each
// line can only be rewritten by its own key, so a file with only one of the
// two directives never lets the other key's value leak onto the wrong line.
func TestSetPHPLimitLinesKeyIndependence(t *testing.T) {
	ini := "post_max_size = 8M\nother_setting = upload_max_filesize = 2M"
	lines := setPHPLimitLines(strings.Split(ini, "\n"), "100M")
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "post_max_size = 100M") {
		t.Errorf("post_max_size not replaced, got %q", got)
	}
	if !strings.Contains(got, "other_setting = upload_max_filesize = 2M") {
		t.Errorf("unrelated line was modified, got %q", got)
	}
}
