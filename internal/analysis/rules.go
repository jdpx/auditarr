package analysis

import (
	"github.com/jdpx/auditarr/internal/models"
)

func ClassifyMedia(
	media models.MediaFile,
	arrFile *models.ArrFile,
	graceHours int,
) (models.MediaClassification, bool) {
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
