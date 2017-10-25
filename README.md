# Canalyze Collect Go - Library in golang to capture CAN bus messages and save to a database for analysis

## Install
* Install libraries and utilities: `> go get github.com/buffersandbeer/canalyzecollect/...`
* Install just the library: `> go get github.com/buffersandbeer/canalyzecollect/`

## Userspace Utilities

* `can-dump` - Dump CAN packets from SocketCan interface and display extended information
* `can-fuzz` - Incrementally fuzz CAN messages
* `can-halfpipe` - Print messages originiating from a target device using a "bump in the wire"

## Docs
Documentation and usage explanations for the library can be found at <https://godoc.org/github.com/buffersandbeer/canalyzecollect>.

## Tests
`> go test` is used for unit testing. No special dependencies are required for testing.

## Library Features

* Write to CAN Bus interface
* Read from CAN Bus interface
* Generate CAN messages
* Process CAN messages
* Pretty Print CAN messages
