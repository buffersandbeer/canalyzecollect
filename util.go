package canalyzecollect

import (
    "os"
)

// fileExists will return true if the provided path exists, false otherwise
func fileExists(path string) bool {
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return false
    }

    return true

}
