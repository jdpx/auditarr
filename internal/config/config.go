package config

import (
	"fmt"
	"net/url"
	"runtime"
)

type Config struct {
	Paths         PathsConfig        `toml:"paths"`
	Sonarr        ArrConfig          `toml:"sonarr"`
	Radarr        ArrConfig          `toml:"radarr"`
	Qbittorrent   QBConfig           `toml:"qbittorrent"`
	Notifications NotificationConfig `toml:"notifications"`
	Outputs       OutputConfig       `toml:"outputs"`
	Suspicious    SuspiciousConfig   `toml:"suspicious"`
	Permissions   PermissionsConfig  `toml:"permissions"`
	PathMappings  map[string]string  `toml:"path_mappings"`
}

type PathsConfig struct {
	MediaRoot   string `toml:"media_root"`
	TorrentRoot string `toml:"torrent_root"`
}

type ArrConfig struct {
	URL        string `toml:"url"`
	APIKey     string `toml:"api_key"`
	GraceHours int    `toml:"grace_hours"`
}

type QBConfig struct {
	URL        string `toml:"url"`
	Username   string `toml:"username"`
	Password   string `toml:"password"`
	GraceHours int    `toml:"grace_hours"`
}

type NotificationConfig struct {
	DiscordWebhook string `toml:"discord_webhook"`
}

type OutputConfig struct {
	ReportDir string `toml:"report_dir"`
}

type SuspiciousConfig struct {
	Extensions   []string `toml:"extensions"`
	FlagArchives bool     `toml:"flag_archives"`
}

type PermissionsConfig struct {
	Enabled             bool     `toml:"enabled"`
	GroupGID            int      `toml:"group_gid"`
	AllowedUIDs         []int    `toml:"allowed_uids"`
	SGIDPaths           []string `toml:"sgid_paths"`
	SkipPaths           []string `toml:"skip_paths"`
	NonstandardSeverity string   `toml:"nonstandard_severity"`
}

func (c *Config) Validate() error {
	if c.Paths.MediaRoot == "" {
		return fmt.Errorf("paths.media_root is required")
	}

	if c.Sonarr.URL != "" {
		if err := validateURL(c.Sonarr.URL, "sonarr.url"); err != nil {
			return err
		}
	}

	if c.Radarr.URL != "" {
		if err := validateURL(c.Radarr.URL, "radarr.url"); err != nil {
			return err
		}
	}

	if c.Qbittorrent.URL != "" {
		if err := validateURL(c.Qbittorrent.URL, "qbittorrent.url"); err != nil {
			return err
		}
	}

	if c.Permissions.NonstandardSeverity == "" {
		c.Permissions.NonstandardSeverity = "warning"
	}

	return nil
}

func validateURL(u, field string) error {
	if u == "" {
		return nil
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL for %s: %w", field, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must use http or https scheme", field)
	}
	return nil
}

func DefaultReportDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "$HOME/Library/Application Support/auditarr/reports"
	case "linux":
		return "/var/lib/auditarr/reports"
	default:
		return "./reports"
	}
}

func DefaultSuspiciousExtensions() []string {
	return []string{
		".exe", ".msi", ".bat", ".cmd", ".com", ".scr",
		".ps1", ".vbs", ".js", ".jar", ".dll", ".sys",
		".reg", ".lnk", ".pif", ".apk", ".dmg", ".pkg",
	}
}
