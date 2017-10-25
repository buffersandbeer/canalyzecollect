package canalyzecollect

import (
    "testing"
    "github.com/buffersandbeer/canlib"
)

// Dummy database type
type TestDB struct{}
func (t TestDB) Close() error { return nil }
func (t TestDB) Ping() bool { return true }
func (t TestDB) AddContext(capturer string, captureName string, details string, target string) (int, error) { return 1, nil }
func (t TestDB) AddCandumpFrame(packet string, context int) error { return nil }
func (t TestDB) AddRawFrame(frame canlib.RawCanFrame, context int) error { return nil }
func (t TestDB) AddProcessedFrame(frame canlib.ProcessedCanFrame, context int) error { return nil }

// TestDBInterfaceValidity ensures that a type that fits the DB interface work
func TestDBInterfaceValidity(t *testing.T) {
    test := TestDB{}
    databaseCheck := func(d Database) bool {
        return true
    }
    if databaseCheck(test) != true {
        t.Error("test struct was not a database")
    }
}
