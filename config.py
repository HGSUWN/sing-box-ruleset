package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"gopkg.in/yaml.v2"
)

// Config holds directories and rule-type mappings
type Config struct {
	LogFile                  string
	RuleDir                  string
	SourceDir                string
	SingboxOutputDirectory   string
	SurgeOutputDirectory     string
	ShadowrocketOutputDirectory string
	ClashOutputDirectory     string
	TrustUpstream            bool
	LsIndex                  int
	EnableTrieFiltering      bool
	LsKeyword                []string
	AdgKeyword               []string
	MapDict                  map[string]string
	MAPReverse               map[string]string
	SingboxToClashMap        map[string]string
	SingboxToSurgeMap        map[string]string

	// 类型白名单
	DomainTypes []string
	IPTypes     []string
}

// NewConfig initializes default Config with type whitelists
func NewConfig() *Config {
	logFile := "log.txt"
	if _, err := os.Stat(logFile); err == nil {
		ioutil.WriteFile(logFile, []byte{}, 0644)
	}
	// 初始化日志
	log.SetOutput(&lumberjackLogger{Filename: logFile})

	c := &Config{
		LogFile:                logFile,
		RuleDir:                "./rule",
		SourceDir:              "./source",
		SingboxOutputDirectory: filepath.Join("./rule", "singbox"),
		SurgeOutputDirectory:   filepath.Join("./rule", "surge"),
		ShadowrocketOutputDirectory: filepath.Join("./rule", "shadowrocket"),
		ClashOutputDirectory:   filepath.Join("./rule", "clash"),
		TrustUpstream:          false,
		LsIndex:                1,
		EnableTrieFiltering:    true,
		LsKeyword:              []string{"little-snitch", "adobe-blocklist"},
		AdgKeyword:             []string{"adguard"},
		MapDict: map[string]string{
			"DOMAIN-SUFFIX":    "domain_suffix",
			"HOST-SUFFIX":      "domain_suffix",
			"DOMAIN":           "domain",
			"HOST":             "domain",
