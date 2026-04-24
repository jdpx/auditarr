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
	mediaRoot      string
	torrentRoot    string
	extraScanPaths []string
}

func NewFilesystemCollector(mediaRoot, torrentRoot string, extraScanPaths []string) *FilesystemCollector {
	return &FilesystemCollector{
		mediaRoot:      mediaRoot,
		torrentRoot:    torrentRoot,
		extraScanPaths: extraScanPaths,
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

	for _, extraPath := range fc.extraScanPaths {
		if extraPath != "" {
			extraFiles, err := fc.collectFromPath(ctx, extraPath, models.MediaSourceExtra)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to collect from extra path %s: %v\n", extraPath, err)
				continue
			}
			allFiles = append(allFiles, extraFiles...)
		}
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
			// Skip hidden directories (but not for extra scan paths like lost+found)
			if source != models.MediaSourceExtra && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		isHidden := strings.HasPrefix(filepath.Base(path), ".")

		// For library/torrent sources: skip hidden files unless they're .parts files
		// For extra sources: collect everything
		if source != models.MediaSourceExtra && isHidden && !strings.HasSuffix(path, ".parts") {
			return nil
		}

		// Skip metadata files (but not for extra scan paths or hidden files)
		if !isHidden && source != models.MediaSourceExtra && analysis.IsMetadataFile(path) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get info for %s: %v\n", path, err)
			return nil
		}

		hardlinkCount, blockSize, err := getFileStats(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get file stats for %s: %v\n", path, err)
			hardlinkCount = 1
			blockSize = info.Size()
		}

		files = append(files, models.MediaFile{
			Path:          path,
			Size:          info.Size(),
			BlockSize:     blockSize,
			ModTime:       info.ModTime(),
			HardlinkCount: hardlinkCount,
			IsHardlinked:  hardlinkCount > 1,
			IsHidden:      isHidden,
			Source:        source,
		})

		return nil
	})

	if err != nil {
		return files, fmt.Errorf("failed to walk root: %w", err)
	}

	return files, nil
}

func getFileStats(path string) (hardlinks int, blockSize int64, err error) {
	var stat syscall.Stat_t
	err = syscall.Stat(path, &stat)
	if err != nil {
		return 0, 0, err
	}
	return int(stat.Nlink), stat.Blocks * 512, nil
}
