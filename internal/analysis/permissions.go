package analysis

import (
	"path/filepath"
)

var metadataPatterns = []string{
	"*-thumb.jpg", "*-thumb.png",
	"poster.jpg", "poster.png",
	"backdrop.jpg", "backdrop.png",
	"folder.jpg", "folder.png",
	"logo.png",
	"logo.svg",
	"season*-poster.jpg", "season*-poster.png",
	"banner.jpg", "landscape.jpg", "clearlogo.png",
	"*.nfo",
	"*.torrent",
}

func IsMetadataFile(path string) bool {
	filename := filepath.Base(path)
	for _, pattern := range metadataPatterns {
		matched, _ := filepath.Match(pattern, filename)
		if matched {
			return true
		}
	}
	return false
}
