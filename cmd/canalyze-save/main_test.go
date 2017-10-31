package main

import (
    "testing"
    "strings"
    "bufio"
    canalyze "github.com/buffersandbeer/canalyzecollect"
)

var testConf = canalyze.Config{DbURI: "postgres://canalyze:PostgresChangeMe!@localhost/canalyze_testing?sslmode=disable"}

func cleanDB() {
    cleanDB, _ := canalyze.CreatePostgres(testConf)
    defer cleanDB.Close()
    var err error
    _, err = cleanDB.Con.Exec(`TRUNCATE canalyze.raw_can_frames, canalyze.capture_context, canalyze.processed_raw_can,
                                canalyze.candump_raw RESTART IDENTITY;`)
    if err != nil {
        panic(err.Error())
    }
}

// TestProcessCandump will make sure the ProcessCandump function appropriately saves entries
func TestProcessCandump(t *testing.T) {
    cleanDB()
    testDB, _ := canalyze.CreatePostgres(testConf)
    defer testDB.Close()
    context, _ := testDB.AddContext("test", "test", "test", "test")
    var testString string = `(1) test0 1#1`
    scanner := bufio.NewScanner(strings.NewReader(testString))
    processCandump(scanner, context, testDB, 1)
    var result int
    err := testDB.Con.QueryRow("SELECT id FROM canalyze.raw_can_frames WHERE capture_interface = 'test0'").Scan(&result)
    if err != nil {
        t.Errorf("database returned an error: " + err.Error())
    }
    if result != 1 {
        t.Errorf("frame not added to the database")
    }
}

// BenchmarkProcessCandump will run benchmarks against ProcessCandump
func BenchmarkProcessCandump(b *testing.B) {
    cleanDB()
    testDB, _ := canalyze.CreatePostgres(testConf)
    defer testDB.Close()
    context, _ := testDB.AddContext("test", "test", "test", "test")
    var testString string = `(1) test0 1#1`
    scanner := bufio.NewScanner(strings.NewReader(testString))
    b.ResetTimer()
    for i := 0; i < b.N; i ++ {
        processCandump(scanner, context, testDB, 1)
    }
}
