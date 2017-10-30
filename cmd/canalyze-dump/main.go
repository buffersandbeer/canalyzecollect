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

    c := make(chan canlib.RawCanFrame, 100)
    p := make(chan canlib.ProcessedCanFrame, 1000)
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
    go handleCan(c, p, *caniface, *quiet)
    go handleDB(p, database, context)
    test := <-errChan
    panic(test.Error())
}

// Process the can message
func handleCan(ch <-chan canlib.RawCanFrame, pch chan<- canlib.ProcessedCanFrame, ifaceName string, quiet bool) {
    processedCan := canlib.ProcessedCanFrame{}
    for rawCan := range ch {
        canlib.ProcessRawCan(&processedCan, rawCan)
        pch <- processedCan
        if !quiet {
            fmt.Println(canlib.ProcessedCanFrameToString(processedCan, "\t"))
        }
    }
}

// Add the can message to the database
func handleDB(pch <-chan canlib.ProcessedCanFrame, db canalyze.Database, context int) {
    for processedCan := range pch {
        err := db.AddProcessedFrame(processedCan, context)
        if err != nil {
            panic(err.Error())
        }
    }
}
