package main

import (
    "github.com/buffersandbeer/canlib"
    canalyze "github.com/buffersandbeer/canalyzecollect"
    "flag"
    "os"
    "bufio"
	"encoding/hex"
    "strings"
    "strconv"
    "runtime"
)

func main() {
    runtime.GOMAXPROCS(4)
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
    check(err)

    defer file.Close()

    if *candump {
        processCandump(file, context, database, workers)
    }

}

func processCandump(file *os.File, context int, db canalyze.Database, workers int) {
    scanner := bufio.NewScanner(file)
    framechan := make(chan canlib.ProcessedCanFrame, 10000)
    for worker := 0; worker < workers; worker++ {
        go testConcurrent(framechan, db, context)
    }
    rawFrame := canlib.RawCanFrame{}
    processedFrame := canlib.ProcessedCanFrame{}
    for scanner.Scan() {
        canlib.ProcessCandump(&rawFrame, scanner.Text())
		canlib.ProcessRawCan(&processedFrame, nextFrame)
        framechan<- processedFrame
    }
    check(scanner.Err())
    close(framechan)
}

func check(err error) {
    if err != nil {
        panic(err)
    }
}
// ParseCandumpLine will parse a candump log formatted string and load into a CanalyzeFrame
func ParseCandumpLine(line string) canlib.RawCanFrame {
    splitSpaces := strings.Split(line, " ")
    newFrame := canlib.RawCanFrame{}
    // Clean up Timestamp
    timeOpenStrip := strings.Split(splitSpaces[0], "(")[1]
    timeCloseStrip := strings.Split(timeOpenStrip, ")")[0]
    //parsedLine[0] = timeCloseStrip
    timeTemp, _ := strconv.ParseFloat(timeCloseStrip, 64)
	newFrame.Timestamp = int64(timeTemp * 1000000000)
    // Add Interface
    //parsedLine[1] = splitSpaces[1]
    newFrame.CaptureInterface = splitSpaces[1]

    // Split up Packet by Arbitration ID or Data
    packet := strings.Split(splitSpaces[2], "#")

    // Add Arbitration ID
    //parsedLine[2] = packet[0]
    idTemp, _  := strconv.ParseUint(packet[0], 16, 32)
    newFrame.ID = uint32(idTemp)

    // Add Hex Data
    //parsedLine[3] = packet[1]
    newFrame.Data, _ = hex.DecodeString(packet[1])
    // Return
    return newFrame
}

func testConcurrent(c <-chan canlib.ProcessedCanFrame, db canalyze.Database, context int) {
    for frame := range c {
        db.AddProcessedFrame(frame, context)
    }
}
