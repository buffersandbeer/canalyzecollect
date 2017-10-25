package canalyzecollect

import (
    "testing"
    "os/exec"
)

// TestFileExistsInvalid will ensure that invalid files return false
func TestFileExists(t *testing.T) {
    if fileExists("./foo/bar/foo/bar/foo/bar/foo/bar/blah.txt") == true {
        t.Error("./foo/var/foo/bar/foo/bar/foo/bar/blah.txt is said to exit")
    }
}

// TestFileExistsValid will check to make sure that the valid path returns true
func TestFileExistsValid(t *testing.T) {
    exec.Command("touch", "/tmp/test.txt").Output()
    if fileExists("/tmp/test.txt") == false{
        t.Error("/tmp/test.txt is said to not exist")
    }
}
