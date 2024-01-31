package main

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	TargetUser   string `yaml:"SUBSCRIBE_USER"`
	AuthCode     string `yaml:"AUTH_CODE"`
	ClientId     string `yaml:"CLIENT_ID"`
	TargetUserId string
}

func loadConfig() (*Config, error) {
	var e error
	ret := &Config{}
	f, e := os.Open("config.yaml")
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(f)
	if e != nil {
		return nil, e
	}
	if e = yaml.Unmarshal(b, ret); e != nil {
		return nil, e
	}
	return ret, nil
}
