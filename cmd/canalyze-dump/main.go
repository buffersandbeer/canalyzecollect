package main

import (
    "github.com/buffersandbeer/canlib"
    canalyze "github.com/buffersandbeer/canalyzecollect"
    "flag"
    "fmt"
)

func main() {
    caniface := flag.String("can-interface", "vcan0", "The CAN interface to capture on")
    configPath := flag.String("config-path", "", "The path to the configuration file")
    capName := flag.String("capname", "", "The name of the capture")
    details := flag.String("details", "", "Details about the capture")
    target := flag.String("target", "", "Name of the targeted device")
    quiet := flag.Bool("quiet", false, "Run without printing to stdout")
    flag.Parse()

    c := make(chan canlib.RawCanFrame, 100000)
    errChan := make(chan error)

    config := canalyze.Config{}
    err := config.LoadConfig(*configPath)
    if err != nil {
        panic(err.Error())
    }

    database, err := canalyze.CreatePostgres(config)
    if err != nil {
        panic(err.Error())
    }
    context, err := database.AddContext(config.Capturer, *capName, *details, *target)
    if err != nil {
        panic(err.Error())
    }

    go canlib.CaptureCan(*caniface, c, errChan)
    go handleCan(c, *quiet, context, database)
    test := <-errChan
    panic(test.Error())
}

// Process the can message
func handleCan(ch <-chan canlib.RawCanFrame, quiet bool, context int, db canalyze.Database) {
    processedCan := canlib.ProcessedCanFrame{}
    for rawCan := range ch {
        canlib.ProcessRawCan(&processedCan, rawCan)
        go db.AddProcessedFrame(processedCan, context)
        if !quiet {
            fmt.Println(canlib.ProcessedCanFrameToString(processedCan, "\t"))
        }
    }
}
