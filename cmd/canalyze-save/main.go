package main

import (
    "github.com/buffersandbeer/canlib"
    canalyze "github.com/buffersandbeer/canalyzecollect"
    "flag"
    "os"
    "bufio"
)

func main() {
    configPath := flag.String("config-path", "", "The path to the configuration file")
    candump := flag.Bool("candump", true, "save Socketcan/Candump Log fomatted captures")
    capName := flag.String("capname", "", "Name of the capture")
    details := flag.String("details", "", "Details about the capture")
    target := flag.String("target", "", "Name of the targeted device or network")
    toSave := flag.String("log", "", "File to save to database")
    workers := *flag.Int("workers", 2, "Number of threads to use to upload frames")

    flag.Parse()

    config := canalyze.Config{}
    err := config.LoadConfig(*configPath)
    check(err)

    database, err := canalyze.CreatePostgres(config)
    check(err)

    context, err := database.AddContext(config.Capturer, *capName, *details, *target)
    check(err)

    file, err := os.Open(*toSave)
    scanner := bufio.NewScanner(file)
    check(err)

    defer file.Close()

    if *candump {
        processCandump(scanner, context, database, workers)
    }

}

func processCandump(scanner *bufio.Scanner, context int, db canalyze.Database, workers int) {
    framechan := make(chan canlib.ProcessedCanFrame, 10000)
    done := make(chan bool, 1)
    for worker := 0; worker < workers; worker++ {
        go saveConcurrent(framechan, db, context, done)
    }
    rawFrame := canlib.RawCanFrame{}
    processedFrame := canlib.ProcessedCanFrame{}
    for scanner.Scan() {
        canlib.ProcessCandump(&rawFrame, scanner.Text())
		canlib.ProcessRawCan(&processedFrame, rawFrame)
        framechan<- processedFrame
    }
    check(scanner.Err())
    close(framechan)
    for worker := 0; worker < workers; worker ++ {
        <-done
    }
}

func check(err error) {
    if err != nil {
        panic(err)
    }
}

func saveConcurrent(c <-chan canlib.ProcessedCanFrame, db canalyze.Database, context int, done chan<- bool) {
    for frame := range c {
        db.AddProcessedFrame(frame, context)
    }
    done<- true
}
