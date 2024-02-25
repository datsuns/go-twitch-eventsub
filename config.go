package main

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	configFilePath     = "config.yaml"
	notifySoundDefault = "C:\\Windows\\Media\\chimes.wav"
)

type Config struct {
	TargetUser      string   `yaml:"SUBSCRIBE_USER"`
	AuthCode        string   `yaml:"AUTH_CODE"`
	ClientId        string   `yaml:"CLIENT_ID"`
	ChatTargets     []string `yaml:"CHART_TARGETS"`
	TargetUserId    string
	StatsLogPath    string
	RaidLogPath     string
	NotifySoundFile string `yaml:"NOTIFY_SOUND"`
}

func loadConfigFrom(raw []byte) (*Config, error) {
	ret := &Config{NotifySoundFile: notifySoundDefault}
	if e := yaml.Unmarshal(raw, ret); e != nil {
		return nil, e
	}
	ret.StatsLogPath = StatsLogPath
	ret.RaidLogPath = RaidLogPath
	return ret, nil
}

func loadConfig() (*Config, error) {
	var e error
	f, e := os.Open(configFilePath)
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(f)
	if e != nil {
		return nil, e
	}
	return loadConfigFrom(b)
}
