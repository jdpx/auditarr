package models

import "time"

type MediaFile struct {
	Path          string
	Size          int64
	ModTime       time.Time
	HardlinkCount int
	IsHardlinked  bool
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
