package canalyzecollect

import (
    "github.com/buffersandbeer/canlib"
)

// Database is an interface that defines a type that can interact with the various databases this framework supports
type Database interface {
    Close() error // Close the connection to the database
    Ping() bool // Check that the database is still there
    AddContext(capturer string, captureName string, details string, target string) (int ,error) // Create context entry
    AddCandumpFrame(packet string, context int) error // Add unparsed data from SocketCan/Candump to the database
    AddRawFrame(frame canlib.RawCanFrame, context int) error // Add raw frames to the database that have not been processed
    AddProcessedFrame(frame canlib.ProcessedCanFrame, context int) error // Add processed frames to the database
}
