package main

import (
    "github.com/buffersandbeer/canlib"
    canalyze "github.com/buffersandbeer/canalyzecollect"
    "flag"
)

func main() {
    caniface := flag.String("can-interface", "vcan0", "The CAN interface to capture on")
    configPath := flag.String("config-path", "", "The path to the configuration file")
    capName := flag.String("capname", "", "The name of the capture")
    details := flag.String("details", "", "Details about the capture")
    target := flag.String("target", "", "Name of the targeted device")
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

    for frame := range c {
        go database.AddRawFrame(frame, context)
    }
}
