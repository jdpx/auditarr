package models

import "time"

type MediaFileSource string

const (
	MediaSourceLibrary MediaFileSource = "library"
	MediaSourceTorrent MediaFileSource = "torrent"
	MediaSourceExtra   MediaFileSource = "extra"
)

type MediaFile struct {
	Path          string
	Size          int64
	BlockSize     int64
	ModTime       time.Time
	HardlinkCount int
	IsHardlinked  bool
	IsHidden      bool
	Source        MediaFileSource
}

func (m *MediaFile) WithinGraceWindow(hours int) bool {
	if hours <= 0 {
		return false
	}
	elapsed := time.Since(m.ModTime)
	if elapsed < 0 {
		return true
	}
	return elapsed < time.Duration(hours)*time.Hour
}
