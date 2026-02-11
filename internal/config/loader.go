package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Outputs.ReportDir == "" {
		c.Outputs.ReportDir = DefaultReportDir()
	}

	if c.Sonarr.GraceHours == 0 {
		c.Sonarr.GraceHours = 48
	}

	if c.Radarr.GraceHours == 0 {
		c.Radarr.GraceHours = 48
	}

	if c.Qbittorrent.GraceHours == 0 {
		c.Qbittorrent.GraceHours = 24
	}

	if len(c.Suspicious.Extensions) == 0 {
		c.Suspicious.Extensions = DefaultSuspiciousExtensions()
	}

	c.applyDefaultPathMappings()
}

func (c *Config) applyDefaultPathMappings() {
	if len(c.PathMappings) > 0 {
		return
	}

	c.PathMappings = make(map[string]string)

	if c.Paths.MediaRoot != "" {
		c.PathMappings["/data/media"] = c.Paths.MediaRoot
	}

	if c.Paths.TorrentRoot != "" {
		c.PathMappings["/data/torrents"] = c.Paths.TorrentRoot
	}
}

func (c *Config) GetReportPath() string {
	reportDir := c.Outputs.ReportDir
	if reportDir == "" {
		reportDir = DefaultReportDir()
	}

	if (len(reportDir) >= 1 && reportDir[:1] == "~") || (len(reportDir) >= 5 && reportDir[:5] == "$HOME") {
		home, _ := os.UserHomeDir()
		if home != "" {
			if reportDir[:1] == "~" {
				reportDir = filepath.Join(home, reportDir[1:])
			} else {
				reportDir = filepath.Join(home, reportDir[6:])
			}
		}
	}

	return reportDir
}
