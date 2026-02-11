package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jdpx/auditarr/internal/analysis"
	"github.com/jdpx/auditarr/internal/models"
)

type Collector interface {
	Collect(ctx context.Context) ([]models.MediaFile, error)
	Name() string
}

type FilesystemCollector struct {
	mediaRoot   string
	torrentRoot string
}

func NewFilesystemCollector(mediaRoot, torrentRoot string) *FilesystemCollector {
	return &FilesystemCollector{
		mediaRoot:   mediaRoot,
		torrentRoot: torrentRoot,
	}
}

func (fc *FilesystemCollector) Name() string {
	return "filesystem"
}

func (fc *FilesystemCollector) Collect(ctx context.Context) ([]models.MediaFile, error) {
	var allFiles []models.MediaFile

	if fc.mediaRoot != "" {
		mediaFiles, err := fc.collectFromPath(ctx, fc.mediaRoot, models.MediaSourceLibrary)
		if err != nil {
			return nil, fmt.Errorf("failed to collect from media root: %w", err)
		}
		allFiles = append(allFiles, mediaFiles...)
	}

	if fc.torrentRoot != "" {
		torrentFiles, err := fc.collectFromPath(ctx, fc.torrentRoot, models.MediaSourceTorrent)
		if err != nil {
			return nil, fmt.Errorf("failed to collect from torrent root: %w", err)
		}
		allFiles = append(allFiles, torrentFiles...)
	}

	return allFiles, nil
}

func (fc *FilesystemCollector) collectFromPath(ctx context.Context, root string, source models.MediaFileSource) ([]models.MediaFile, error) {
	var files []models.MediaFile

	if _, err := os.Stat(root); os.IsNotExist(err) {
		return files, fmt.Errorf("root does not exist: %s", root)
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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

		if analysis.IsMetadataFile(path) {
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
			Source:        source,
		})

		return nil
	})

	if err != nil {
		return files, fmt.Errorf("failed to walk root: %w", err)
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
