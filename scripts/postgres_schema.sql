CREATE SCHEMA canalyze;

CREATE TABLE canalyze.capture_context ( 
    id                   serial  NOT NULL,
    capturer             varchar  NOT NULL,
    capture_name         varchar(255)  NOT NULL,
    details              text  NOT NULL,
    target               varchar(255)  ,
    CONSTRAINT pk_capture_context PRIMARY KEY ( id )
 );

COMMENT ON TABLE canalyze.capture_context IS 'Packet capture context for CAN analysis';

COMMENT ON COLUMN canalyze.capture_context.id IS 'Unique identifier for a capture context';

COMMENT ON COLUMN canalyze.capture_context.capturer IS 'Friendly name of the device or system performing the capture';

COMMENT ON COLUMN canalyze.capture_context.capture_name IS 'The name of the specific capture';

COMMENT ON COLUMN canalyze.capture_context.details IS 'Details about packet capture';

COMMENT ON COLUMN canalyze.capture_context.target IS 'Optional field to identify targeted device';

CREATE TABLE canalyze.raw_can_frames ( 
    id                   serial  NOT NULL,
    original_can_id      bigint  ,
    can_id               bigint  NOT NULL,
    data_length_code     integer  NOT NULL,
    extended_frame_flag  bool  ,
    remote_transmission_request_flag bool  ,
    error_flag           bool  ,
    payload              bytea  ,
    context_id           integer  NOT NULL,
    timestamp_nano       bigint  NOT NULL,
    capture_interface    varchar  NOT NULL,
    CONSTRAINT pk_raw_can_frame PRIMARY KEY ( id )
 );

CREATE INDEX idx_raw_can_packets ON canalyze.raw_can_frames ( context_id );

COMMENT ON TABLE canalyze.raw_can_frames IS 'Storage table for raw CAN frames. This table supports both canlib/canalyze captured packets as well as candump captured packets';

COMMENT ON COLUMN canalyze.raw_can_frames.id IS 'Unique identifer for a single instance of a raw can packet';

COMMENT ON COLUMN canalyze.raw_can_frames.original_can_id IS 'Original CAN ID before masks applied';

COMMENT ON COLUMN canalyze.raw_can_frames.can_id IS 'CAN ID after masks have been applied';

COMMENT ON COLUMN canalyze.raw_can_frames.data_length_code IS 'Length of the data in the CAN packet';

COMMENT ON COLUMN canalyze.raw_can_frames.extended_frame_flag IS 'CAN Extended Frame Flag';

COMMENT ON COLUMN canalyze.raw_can_frames.remote_transmission_request_flag IS 'RTR Flag for CAN';

COMMENT ON COLUMN canalyze.raw_can_frames.error_flag IS 'CAN Error Flag';

COMMENT ON COLUMN canalyze.raw_can_frames.payload IS 'Data within the CAN packet';

COMMENT ON COLUMN canalyze.raw_can_frames.context_id IS 'Links the frame to the context for its capture';

COMMENT ON COLUMN canalyze.raw_can_frames.timestamp_nano IS 'Timestamp that the packet was captured at in nanoseconds';

COMMENT ON COLUMN canalyze.raw_can_frames.capture_interface IS 'The interface that this frame was captured on';

CREATE TABLE canalyze.candump_raw ( 
    id                   serial  NOT NULL,
    frame                text  NOT NULL,
    context_id           integer  NOT NULL,
    CONSTRAINT pk_candump_raw PRIMARY KEY ( id )
 );

CREATE INDEX idx_candump_raw ON canalyze.candump_raw ( context_id );

COMMENT ON TABLE canalyze.candump_raw IS 'Table for storing raw captures from the SocketCAN candump utility.';

COMMENT ON COLUMN canalyze.candump_raw.id IS 'Unique identifier for packet';

COMMENT ON COLUMN canalyze.candump_raw.frame IS 'Packet information';

COMMENT ON COLUMN canalyze.candump_raw.context_id IS 'Link to the context of the capture';

CREATE TABLE canalyze.processed_raw_can ( 
    frame_hash           varchar(64)  NOT NULL,
    frame_id             integer  ,
    ascii_in_data        varchar  NOT NULL
 );

CREATE INDEX idx_processed_raw_can ON canalyze.processed_raw_can ( frame_id );

COMMENT ON TABLE canalyze.processed_raw_can IS 'Table containing additional information about captured CAN packets';

COMMENT ON COLUMN canalyze.processed_raw_can.frame_hash IS 'hash of can_id + data for creating a single unique identifier for each id/data combination';

COMMENT ON COLUMN canalyze.processed_raw_can.frame_id IS 'ID of the raw can frame this extends';

COMMENT ON COLUMN canalyze.processed_raw_can.ascii_in_data IS 'Any Ascii values stored with the payload';

ALTER TABLE canalyze.candump_raw ADD CONSTRAINT fk_candump_raw_capture_context FOREIGN KEY ( context_id ) REFERENCES canalyze.capture_context( id ) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE canalyze.processed_raw_can ADD CONSTRAINT fk_processed_raw_can FOREIGN KEY ( frame_id ) REFERENCES canalyze.raw_can_frames( id );

ALTER TABLE canalyze.raw_can_frames ADD CONSTRAINT fk_context_id FOREIGN KEY ( context_id ) REFERENCES canalyze.capture_context( id );


