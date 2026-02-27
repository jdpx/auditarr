package reporting

import (
	"fmt"
	"time"

	"github.com/jdpx/auditarr/internal/models"
)

func filterByClassification(classified []models.ClassifiedMedia, class models.MediaClassification) []models.ClassifiedMedia {
	var result []models.ClassifiedMedia
	for _, cm := range classified {
		if cm.Classification == class {
			result = append(result, cm)
		}
	}
	return result
}

func formatDuration(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < time.Hour*24 {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	if d < time.Hour*24*30 {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	return fmt.Sprintf("%d months", int(d.Hours()/24/30))
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)

	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
