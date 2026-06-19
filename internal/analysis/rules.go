package analysis

import (
	"github.com/jdpx/auditarr/internal/models"
)

func ClassifyMedia(
	media models.MediaFile,
	arrFile *models.ArrFile,
	graceHours int,
) (models.MediaClassification, bool) {
	if media.IsHidden {
		return models.MediaHiddenFile, true
	}

	if graceHours <= 0 {
		graceHours = 0
	}

	if media.WithinGraceWindow(graceHours) {
		return "", false
	}

	if arrFile == nil {
		return models.MediaOrphan, true
	}

	if media.IsHardlinked {
		return models.MediaHealthy, true
	}

	return models.MediaAtRisk, true
}

func ClassifyTorrentFile(
	media models.MediaFile,
	arrFile *models.ArrFile,
	graceHours int,
	inActiveTorrent bool,
) (models.MediaClassification, bool) {
	if media.IsHidden {
		return models.MediaHiddenFile, true
	}

	if graceHours <= 0 {
		graceHours = 0
	}

	if media.WithinGraceWindow(graceHours) {
		return "", false
	}

	if media.IsHardlinked {
		return models.MediaHealthy, true
	}

	// A file is only an orphaned download if it is NOT tracked by Arr AND is not
	// part of a torrent still managed by qBittorrent. A torrent the client still
	// holds is being seeded (e.g. to meet a private-tracker ratio/seed-time
	// requirement) or is waiting to be imported — deleting it would break the
	// torrent and lose wanted, not-yet-imported content. Only once qBittorrent no
	// longer manages it is the leftover file genuinely orphaned.
	if arrFile == nil && !inActiveTorrent {
		return models.MediaOrphanedDownload, true
	}

	return models.MediaHealthy, true
}

func ClassifyExtraFile(media models.MediaFile) (models.MediaClassification, bool) {
	return models.MediaLostAndFound, true
}
