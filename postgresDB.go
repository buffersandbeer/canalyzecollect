package canalyzecollect

import (
    _ "github.com/lib/pq" // Need to load the Postgres driver since this is core to the library
    "database/sql"
    "errors"
    "github.com/buffersandbeer/canlib"
)

// PostgresDB will manage transactions with a PostgreSQL database
type PostgresDB struct {
    Con *sql.DB
    Connected bool
    addRawStatement *sql.Stmt
    addProcessedStatement *sql.Stmt
    addContextStatement *sql.Stmt
    addCandumpRaw *sql.Stmt
}

// CreatePostgres will connect to the Postgres DB and update the pdb struct to contain that connection
func CreatePostgres(conf Config) (*PostgresDB, error) {
    db, err := sql.Open("postgres", conf.DbURI)
    if err != nil {
        return nil, errors.New("DB returned an error: " + err.Error())
    }
    newDB := PostgresDB{}
    newDB.Con = db
    var connected bool
    connected, err = newDB.Ping()
    if err != nil{
        return &newDB, errors.New("failed to connect to database: " + err.Error())
    }
    newDB.Connected = connected

    // Prepare key statements
	newDB.addContextStatement, _ = db.Prepare(`INSERT INTO canalyze.capture_context (capturer, capture_name, details, target)
					                             VALUES($1, $2, $3, $4) RETURNING id;`)

    newDB.addRawStatement, _ = db.Prepare(`INSERT INTO canalyze.raw_can_frames (original_can_id, can_id, 
                                                data_length_code, extended_frame_flag,
                                                remote_transmission_request_flag, error_flag, payload, context_id,
                                                timestamp_nano, capture_interface) VALUES($1, $2, $3, $4, $5, $6,
                                                $7, $8, $9, $10);`)
    newDB.addProcessedStatement, _ = db.Prepare(`WITH raw AS (
                                                    INSERT INTO canalyze.raw_can_frames (original_can_id, can_id, 
                                                        data_length_code, extended_frame_flag,
                                                        remote_transmission_request_flag, error_flag, payload, context_id,
                                                        timestamp_nano, capture_interface) VALUES($1, $2, $3, $4, $5, $6,
                                                        $7, $8, $9, $10) returning id AS raw_id
                                                 ) INSERT INTO canalyze.processed_raw_can(frame_hash, frame_id, ascii_in_data)
                                                        SELECT $11, raw_id, $12 FROM raw;`)
    newDB.addCandumpRaw, err = db.Prepare(`INSERT INTO canalyze.candump_raw (frame, context_id) VALUES ($1, $2)`)

    if err != nil {
        return &newDB, errors.New("error creating prepared statement: " + err.Error())
    }
    return &newDB, nil
}

// Ping will try to ping the database
func (pdb PostgresDB) Ping() (bool, error) {
    err := pdb.Con.Ping()
    if err != nil {
        return false, err
    }
    return true, nil
}

// AddContext will add a context row to the database and return the ID of that context
func (pdb PostgresDB) AddContext(capturer string, captureName string, details string, target string) (int, error) {
	var id int
	err := pdb.addContextStatement.QueryRow(capturer, captureName, details, target).Scan(&id)
	if err != nil {
		return 0, errors.New("database insert returned an error: " + err.Error())
	}

	return id, nil
}

// AddRawFrame will add a raw frame to the database
func (pdb PostgresDB) AddRawFrame(frame canlib.RawCanFrame, context int) error {
    _, err := pdb.addRawStatement.Exec(frame.OID, frame.ID, frame.Dlc, frame.Eff, frame.Rtr, frame.Err,
                        frame.Data, context, frame.Timestamp, frame.CaptureInterface)
    if err != nil {
        return errors.New("db returned an error: " + err.Error())
    }

    return nil
}

// AddProcessedFrame will add a processed can frame into the database
func (pdb PostgresDB) AddProcessedFrame(frame canlib.ProcessedCanFrame, context int) error {
    _, err := pdb.addProcessedStatement.Exec(frame.Packet.OID, frame.Packet.ID, frame.Packet.Dlc, frame.Packet.Eff,
                        frame.Packet.Rtr, frame.Packet.Err, frame.Packet.Data, context, frame.Packet.Timestamp,
                        frame.Packet.CaptureInterface, frame.PacketHash, frame.AlphaNumData)
    if err != nil {
        return errors.New("db returned an error adding processed info: " + err.Error())
    }
    return nil
}

// AddCandumpFrame will add a can frame captured by Socketcan/candump to the database
func (pdb PostgresDB) AddCandumpFrame(packet string, context int) error {
    _, err := pdb.addCandumpRaw.Exec(packet, context)
    if err != nil {
        return errors.New("db returned an error: " + err.Error())
    }
    return nil
}

// Close will close the database connection
func (pdb *PostgresDB) Close() error{
    var err error
    err = pdb.Con.Close()
    pdb.Connected = false
    return err
}
