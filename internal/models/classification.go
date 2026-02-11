package models

import "time"

type MediaClassification string

const (
	MediaHealthy          MediaClassification = "healthy"
	MediaAtRisk           MediaClassification = "at_risk"
	MediaOrphan           MediaClassification = "orphan"
	MediaOrphanedDownload MediaClassification = "orphaned_download"
)

type ClassifiedMedia struct {
	File           MediaFile
	KnownToArr     bool
	ArrSource      string
	Classification MediaClassification
	Reason         string
}

type ArrFile struct {
	Path       string
	SeriesID   int
	EpisodeID  int
	MovieID    int
	Monitored  bool
	ImportDate time.Time
}

func (af *ArrFile) IsKnown() bool {
	return af != nil && af.Path != "" && (af.SeriesID > 0 || af.MovieID > 0)
}
