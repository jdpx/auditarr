package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jdpx/auditarr/internal/models"
)

func CollectPermissions(root string, skipPaths []string) ([]models.FilePermissions, error) {
	var permissions []models.FilePermissions

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				fmt.Fprintf(os.Stderr, "Warning: permission denied: %s\n", path)
				return nil
			}
			return err
		}

		if shouldSkipPath(path, skipPaths) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to stat %s: %v\n", path, err)
			return nil
		}

		permissions = append(permissions, models.FilePermissions{
			Path:        path,
			Mode:        uint32(stat.Mode),
			OwnerUID:    int(stat.Uid),
			GroupGID:    int(stat.Gid),
			IsDirectory: d.IsDir(),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skip := range skipPaths {
		if strings.HasPrefix(path, skip) {
			return true
		}
	}
	return false
}

func IsMediaFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	mediaExts := []string{".mkv", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg", ".mpeg", ".ts"}
	for _, me := range mediaExts {
		if ext == me {
			return true
		}
	}
	return false
}

func IsSubtitleFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	subtitleExts := []string{".srt", ".ass", ".ssa", ".vtt", ".sub", ".idx", ".pgs"}
	for _, se := range subtitleExts {
		if ext == se {
			return true
		}
	}
	return false
}

func NormalizePath(path string, mappings map[string]string) string {
	if mappings == nil || len(mappings) == 0 {
		return filepath.Clean(path)
	}

	normalized := filepath.Clean(path)

	for apiPath, fsPath := range mappings {
		apiPathClean := filepath.Clean(apiPath)
		if strings.HasPrefix(normalized, apiPathClean) {
			relative := strings.TrimPrefix(normalized, apiPathClean)
			normalized = filepath.Join(fsPath, relative)
			break
		}
	}

	return normalized
}

func NormalizePathReverse(path string, mappings map[string]string) string {
	if mappings == nil || len(mappings) == 0 {
		return filepath.Clean(path)
	}

	normalized := filepath.Clean(path)

	for apiPath, fsPath := range mappings {
		fsPathClean := filepath.Clean(fsPath)
		if strings.HasPrefix(normalized, fsPathClean) {
			relative := strings.TrimPrefix(normalized, fsPathClean)
			normalized = filepath.Join(apiPath, relative)
			break
		}
	}

	return normalized
}
