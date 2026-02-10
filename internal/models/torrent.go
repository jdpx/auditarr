package models

import "time"

type TorrentState string

const (
	StateDownloading TorrentState = "downloading"
	StateChecking    TorrentState = "checking"
	StateCompleted   TorrentState = "completed"
	StatePaused      TorrentState = "paused"
	StateStalled     TorrentState = "stalled"
)

type Torrent struct {
	Hash        string
	Name        string
	SavePath    string
	State       TorrentState
	CompletedOn time.Time
	Files       []string
}

func (t *Torrent) IsActive() bool {
	return t.State == StateDownloading || t.State == StateChecking
}

func (t *Torrent) WithinGraceWindow(hours int) bool {
	if hours <= 0 {
		return false
	}
	if t.CompletedOn.IsZero() {
		return true
	}
	elapsed := time.Since(t.CompletedOn)
	if elapsed < 0 {
		return true
	}
	return elapsed < time.Duration(hours)*time.Hour
}
