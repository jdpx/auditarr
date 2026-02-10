package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jdpx/auditarr/internal/models"
)

type Collector interface {
	Collect(ctx context.Context) ([]models.MediaFile, error)
	Name() string
}

type FilesystemCollector struct {
	mediaRoot string
}

func NewFilesystemCollector(mediaRoot string) *FilesystemCollector {
	return &FilesystemCollector{
		mediaRoot: mediaRoot,
	}
}

func (fc *FilesystemCollector) Name() string {
	return "filesystem"
}

func (fc *FilesystemCollector) Collect(ctx context.Context) ([]models.MediaFile, error) {
	var files []models.MediaFile

	if fc.mediaRoot == "" {
		return files, fmt.Errorf("media root not configured")
	}

	if _, err := os.Stat(fc.mediaRoot); os.IsNotExist(err) {
		return files, fmt.Errorf("media root does not exist: %s", fc.mediaRoot)
	}

	err := filepath.WalkDir(fc.mediaRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				fmt.Fprintf(os.Stderr, "Warning: permission denied: %s\n", path)
				return nil
			}
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasPrefix(filepath.Base(path), ".") {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get info for %s: %v\n", path, err)
			return nil
		}

		hardlinkCount, err := getHardlinkCount(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get hardlink count for %s: %v\n", path, err)
			hardlinkCount = 1
		}

		files = append(files, models.MediaFile{
			Path:          path,
			Size:          info.Size(),
			ModTime:       info.ModTime(),
			HardlinkCount: hardlinkCount,
			IsHardlinked:  hardlinkCount > 1,
		})

		return nil
	})

	if err != nil {
		return files, fmt.Errorf("failed to walk media root: %w", err)
	}

	return files, nil
}

func getHardlinkCount(path string) (int, error) {
	var stat syscall.Stat_t
	err := syscall.Stat(path, &stat)
	if err != nil {
		return 0, err
	}
	return int(stat.Nlink), nil
}
