package canalyzecollect

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "errors"
)

// Config contains the configuration to be used by canalyze
type Config struct {
    DbURI string
    Capturer string
}

// LoadConfig loads the configuration file based upon the file path provided
//
// If the file does not exist or is not accessible, LoadConfig will return an error
func (c *Config) LoadConfig(path string) error {
    if fileExists(path) != true {
        return errors.New("config file does not exist")
    }

    yamlFile, err := ioutil.ReadFile(path)
    if err != nil {
        return errors.New("error reading config file: " + err.Error())
    }

    err = yaml.Unmarshal(yamlFile, c)
    if err != nil {
        return errors.New("error parsing config file: " + err.Error())
    }

    return nil
}
