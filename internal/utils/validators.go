package utils

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func ValidateConfigPath(path string) error {
	if path == "" {
		return fmt.Errorf("config path is required")
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("config path is a directory, not a file: %s", path)
	}

	return nil
}

func ValidateURL(u string) error {
	if u == "" {
		return nil
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL must use http or https scheme")
	}

	if parsed.Host == "" {
		return fmt.Errorf("URL must have a host")
	}

	return nil
}

func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		if home != "" {
			return strings.Replace(path, "~", home, 1)
		}
	}

	if strings.HasPrefix(path, "$HOME/") {
		home, _ := os.UserHomeDir()
		if home != "" {
			return strings.Replace(path, "$HOME", home, 1)
		}
	}

	return path
}
