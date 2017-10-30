package canalyzecollect

import (
    _ "github.com/lib/pq"
    "testing"
    "github.com/buffersandbeer/canlib"
)

var testConf = Config{DbURI: "postgres://canalyze:PostgresChangeMe!@localhost/canalyze_testing?sslmode=disable"}

func cleanDB() {
    cleanDB, _ := CreatePostgres(testConf)
    var err error
    _, err = cleanDB.con.Exec(`TRUNCATE canalyze.raw_can_frames, canalyze.capture_context, canalyze.processed_raw_can,
                                canalyze.candump_raw RESTART IDENTITY;`)
    if err != nil {
        panic(err.Error())
    }
}

// TestCreatePostgres will check that the CreatePostgres function successfully creates Postgres connection
func TestCreatePostgres(t *testing.T) {
    result, err := CreatePostgres(testConf)
    if err != nil {
        t.Errorf("Function returned an error: " + err.Error())
    }
    if result.connected != true {
        t.Errorf("Postgres object was not created successfully")
    }
}

// TestPostgresPing will verify that the postgres object can successfully ping the database
func TestPostgresPing(t *testing.T) {
    testdb, err := CreatePostgres(testConf)
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

// TestPostgresAddContext will verify that one can add context to the database
func TestPostgresAddContext(t *testing.T) {
    cleanDB()
    testDB, _ := CreatePostgres(testConf)
    id, err := testDB.AddContext("testCap", "testCapName", "testDeets", "testTarget")
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    if id != 1 {
        t.Errorf("%d != 1",id)
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
    contextID, _ := testDB.AddContext("test", "test", "test", "test")
    err := testDB.AddRawFrame(testRawFrame, contextID)
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    var result uint32
    err = testDB.con.QueryRow("SELECT can_id FROM canalyze.raw_can_frames WHERE can_id = 1;").Scan(&result)
    if err != nil {
        t.Errorf("database returned an error: " + err.Error())
    }
    if result != 1 {
        t.Errorf("new raw frame was not added to the database")
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
    contextID, _ := testDB.AddContext("test", "test", "test", "test")
    err := testDB.AddProcessedFrame(testProcessedFrame, contextID)
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    var result int
    err = testDB.con.QueryRow("SELECT frame_id FROM canalyze.processed_raw_can WHERE frame_hash = 'test'").Scan(&result)
    if err != nil {
        t.Errorf("database returned an error: " + err.Error())
    }
    if result != 1 {
        t.Errorf("%d != test", result)
    }
}

// TestPostgresAddCandumpFrame will verify that raw candump frames can be added to the database
func TestPostgresAddCandumpFrame(t *testing.T) {
    cleanDB()
    testFrame := "test"
    testDB, _ := CreatePostgres(testConf)
    context, _ := testDB.AddContext("test", "test", "test", "test")
    err := testDB.AddCandumpFrame(testFrame, context)
    if err != nil {
        t.Errorf("function returned an error: " + err.Error())
    }
    var result int
    err = testDB.con.QueryRow("SELECT id FROM canalyze.candump_raw WHERE frame = 'test';").Scan(&result)
    if err != nil {
        t.Errorf("database returned an error: " + err.Error())
    }
    if result != 1 {
        t.Errorf("%d != 1", result)
    }
}
