package canalyzecollect

import (
    _ "github.com/lib/pq"
    "testing"
    "github.com/buffersandbeer/canlib"
)

var testConf = Config{DbURI: "postgres://canalyze:PostgresChangeMe!@localhost/canalyze_testing?sslmode=disable"}

func cleanDB() {
    cleanDB, _ := CreatePostgres(testConf)
    defer cleanDB.Close()
    var err error
    _, err = cleanDB.Con.Exec(`TRUNCATE canalyze.raw_can_frames, canalyze.capture_context, canalyze.processed_raw_can,
                                canalyze.candump_raw RESTART IDENTITY;`)
    if err != nil {
        panic(err.Error())
    }
}

// TestCreatePostgres will check that the CreatePostgres function successfully creates Postgres connection
func TestCreatePostgres(t *testing.T) {
    result, err := CreatePostgres(testConf)
    defer result.Close()
    if err != nil {
        t.Errorf("Function returned an error: " + err.Error())
    }
    if result.Connected != true {
        t.Errorf("Postgres object was not created successfully")
    }
}

// TestPostgresPing will verify that the postgres object can successfully ping the database
func TestPostgresPing(t *testing.T) {
    testdb, err := CreatePostgres(testConf)
    defer testdb.Close()
    if err != nil {
        t.Errorf("Error connecting to database: " + err.Error())
    }
    var result bool
    result, err = testdb.Ping()
    if err != nil {
        t.Errorf("ping returned an error: " + err.Error())
    }
    if result != true {
        t.Errorf("failed to ping database")
    }
}

// BenchmarkPostgresPing will run benchmarks against the postgres version of the ping function
func BenchmarkPostgresPing(b *testing.B) {
    testdb, _ := CreatePostgres(testConf)
    defer testdb.Close()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        testdb.Ping()
    }
}

// TestPostgresAddContext will verify that one can add context to the database
func TestPostgresAddContext(t *testing.T) {
    cleanDB()
    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    id, err := testDB.AddContext("testCap", "testCapName", "testDeets", "testTarget")
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    if id != 1 {
        t.Errorf("%d != 1",id)
    }
}

// BenchmarkPostgresAddContext will run benchmarks against the postgresql version of Add Context
func BenchmarkPostgresAddContext(b *testing.B) {
    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        testDB.AddContext("testCap", "testCapName", "testDeets", "testTarget")
    }
}

// TestPostgresAddRawFrame ensures that raw can frames can be added to the database
func TestPostgresAddRawFrame(t *testing.T) {
    cleanDB()

    testRawFrame := canlib.RawCanFrame{ Timestamp: 0,
                                     OID: 1,
                                     ID: 1,
                                     Dlc: 0,
                                     Eff: false,
                                     Rtr: false,
                                     Err: false,
                                     Data: []byte{},
                                     CaptureInterface: "test",
    }

    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    contextID, _ := testDB.AddContext("test", "test", "test", "test")
    err := testDB.AddRawFrame(testRawFrame, contextID)
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    var result uint32
    err = testDB.Con.QueryRow("SELECT can_id FROM canalyze.raw_can_frames WHERE can_id = 1;").Scan(&result)
    if err != nil {
        t.Errorf("database returned an error: " + err.Error())
    }
    if result != 1 {
        t.Errorf("new raw frame was not added to the database")
    }
}

// BenchmarkPostgresAddRawFrame will run benchmarks against the postgres version of AddRawFrame
func BenchmarkPostgresAddRawFrame(b *testing.B) {
    cleanDB()
    testRawFrame := canlib.RawCanFrame{ Timestamp: 0,
                                     OID: 1,
                                     ID: 1,
                                     Dlc: 0,
                                     Eff: false,
                                     Rtr: false,
                                     Err: false,
                                     Data: []byte{},
                                     CaptureInterface: "test",
    }

    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    contextID, _ := testDB.AddContext("test", "test", "test", "test")
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        testDB.AddRawFrame(testRawFrame, contextID)
    }
}

// TestPostgresAddProcessedFrame ensures that processed can frames can be added to the database
func TestPostgresAddProcessedFrame(t *testing.T) {
    cleanDB()

    testRawFrame := canlib.RawCanFrame{ Timestamp: 0,
                                     OID: 1,
                                     ID: 1,
                                     Dlc: 0,
                                     Eff: false,
                                     Rtr: false,
                                     Err: false,
                                     Data: []byte{},
                                     CaptureInterface: "test",
    }
    testProcessedFrame := canlib.ProcessedCanFrame{ Packet: testRawFrame, PacketHash: "test"}
    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    contextID, _ := testDB.AddContext("test", "test", "test", "test")
    err := testDB.AddProcessedFrame(testProcessedFrame, contextID)
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    var result int
    err = testDB.Con.QueryRow("SELECT frame_id FROM canalyze.processed_raw_can WHERE frame_hash = 'test'").Scan(&result)
    if err != nil {
        t.Errorf("database returned an error: " + err.Error())
    }
    if result != 1 {
        t.Errorf("%d != test", result)
    }
}

// BenchmarkPostgresAddProcessedFrame will run benchmarks against the postgres version of AddProcessedFrame
func BenchmarkPostgresAddProcessedFrame(b *testing.B) {
    cleanDB()
    testRawFrame := canlib.RawCanFrame{ Timestamp: 0,
                                     OID: 1,
                                     ID: 1,
                                     Dlc: 0,
                                     Eff: false,
                                     Rtr: false,
                                     Err: false,
                                     Data: []byte{},
                                     CaptureInterface: "test",
    }
    testProcessedFrame := canlib.ProcessedCanFrame{ Packet: testRawFrame, PacketHash: "test"}
    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    contextID, _ := testDB.AddContext("test", "test", "test", "test")
    for i := 0; i < b.N; i++ {
        testDB.AddProcessedFrame(testProcessedFrame, contextID)
    }
}

// TestPostgresAddCandumpFrame will verify that raw candump frames can be added to the database
func TestPostgresAddCandumpFrame(t *testing.T) {
    cleanDB()
    testFrame := "test"
    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    context, _ := testDB.AddContext("test", "test", "test", "test")
    err := testDB.AddCandumpFrame(testFrame, context)
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    var result int
    err = testDB.Con.QueryRow("SELECT id FROM canalyze.candump_raw WHERE frame = 'test';").Scan(&result)
    if err != nil {
        t.Errorf("database returned an error: " + err.Error())
    }
    if result != 1 {
        t.Errorf("%d != 1", result)
    }
}

// BenchmarkPostgresAddCandumpFrame will run benchmarks against the postgres version of AddCandumpFrame
func BenchmarkPostgresAddCandumpFrame(b *testing.B) {
    cleanDB()
    testFrame := "test"
    testDB, _ := CreatePostgres(testConf)
    defer testDB.Close()
    context, _ := testDB.AddContext("test", "test", "test", "test")
    for i := 0; i < b.N; i++ {
        testDB.AddCandumpFrame(testFrame, context)
    }
}

// TestPostgresClose will verify that a database connection is closed after calling the function
func TestPostgresClose(t *testing.T) {
    testDB, _ := CreatePostgres(testConf)
    if testDB.Connected != true {
        t.Errorf("database connection not reported by struct")
    }
    err := testDB.Close()
    if err != nil {
        t.Errorf("closing database returned an error: " + err.Error())
    }
    if testDB.Connected != false {
        t.Errorf("database connection not reported closed by struct")
    }
}

