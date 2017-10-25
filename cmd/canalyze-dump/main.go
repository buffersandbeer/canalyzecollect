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
    flag.Parse()

    c := make(chan canlib.RawCanFrame, 100)
    p := make(chan canlib.ProcessedCanFrame, 1000)
    errChan := make(chan error)

    config := canalyze.Config{}
    err := config.LoadConfig(*configPath)
    if err != nil {
        panic(err.Error())
    }

    database, _ := canalyze.CreatePostgres(config)
    context, _ := database.AddContext(config.Capturer, *capName, *details, *target)

    go canlib.CaptureCan(*caniface, c, errChan)
    go handleCan(c, p, *caniface)
    go handleDB(p, database, context)
    test := <-errChan
    panic(test.Error())
}

// Process the can message
func handleCan(ch <-chan canlib.RawCanFrame, pch chan<- canlib.ProcessedCanFrame, ifaceName string) {
    processedCan := canlib.ProcessedCanFrame{}
    for rawCan := range ch {
        canlib.ProcessRawCan(&processedCan, rawCan, ifaceName)
        pch <- processedCan
        fmt.Println(canlib.RawCanFrameToString(rawCan, "\t"))
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
