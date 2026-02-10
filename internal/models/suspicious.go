package models

import (
	"path/filepath"
	"strings"
)

type SuspiciousFile struct {
	Path   string
	Reason string
}

var defaultSuspiciousExtensions = []string{
	".exe", ".msi", ".bat", ".cmd", ".com", ".scr",
	".ps1", ".vbs", ".js", ".jar", ".dll", ".sys",
	".reg", ".lnk", ".pif", ".apk", ".dmg", ".pkg",
	".iso", ".zip", ".rar", ".7z", ".tar", ".gz",
}

func IsSuspicious(path string, extensions []string, flagArchives bool) (bool, string) {
	if len(extensions) == 0 {
		extensions = defaultSuspiciousExtensions
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false, ""
	}

	for _, susExt := range extensions {
		if ext == susExt {
			if isArchiveExtension(ext) && !flagArchives {
				return false, ""
			}
			return true, "suspicious_extension"
		}
	}

	base := filepath.Base(path)
	parts := strings.Split(base, ".")
	if len(parts) > 2 {
		lastExt := "." + strings.ToLower(parts[len(parts)-1])
		for _, susExt := range extensions {
			if lastExt == susExt && !isMediaExtension(parts[len(parts)-2]) {
				return true, "double_extension"
			}
		}
	}

	return false, ""
}

func isArchiveExtension(ext string) bool {
	archives := []string{".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}
	for _, a := range archives {
		if ext == a {
			return true
		}
	}
	return false
}

func isMediaExtension(ext string) bool {
	media := []string{"mkv", "mp4", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg"}
	for _, m := range media {
		if strings.ToLower(ext) == m {
			return true
		}
	}
	return false
}

type FilePermissions struct {
	Path        string
	Mode        uint32
	OwnerUID    int
	GroupGID    int
	IsDirectory bool
}

func (fp *FilePermissions) ModeString() string {
	mode := fp.Mode & 0777
	result := ""

	if fp.IsDirectory {
		result += "d"
	} else {
		result += "-"
	}

	perms := []uint32{0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001}
	symbols := []string{"r", "w", "x", "r", "w", "x", "r", "w", "x"}

	for i, p := range perms {
		if mode&p != 0 {
			result += symbols[i]
		} else {
			result += "-"
		}
	}

	return result
}

func (fp *FilePermissions) HasSGID() bool {
	return fp.Mode&02000 != 0
}

func (fp *FilePermissions) GroupWritable() bool {
	return fp.Mode&0020 != 0
}

type PermissionIssue struct {
	Path         string
	CurrentMode  uint32
	ExpectedMode uint32
	Owner        int
	Group        int
	Issue        string
	Severity     string
	FixHint      string
}
