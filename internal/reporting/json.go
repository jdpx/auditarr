package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jdpx/auditarr/internal/analysis"
	"github.com/jdpx/auditarr/internal/config"
	"github.com/jdpx/auditarr/internal/models"
)

// JSONReport is a script-friendly output format
type JSONReport struct {
	GeneratedAt       string                   `json:"generated_at"`
	Duration          float64                  `json:"duration_seconds"`
	Summary           JSONSummary              `json:"summary"`
	ConnectionStatus  []analysis.ServiceStatus `json:"connection_status"`
	OrphanedMedia     []JSONFileEntry          `json:"orphaned_media"`
	OrphanedDownloads []JSONFileEntry          `json:"orphaned_downloads"`
	AtRisk            []JSONFileEntry          `json:"at_risk"`
	SuspiciousFiles   []JSONSuspiciousEntry    `json:"suspicious_files"`
	UnlinkedTorrents  []JSONTorrentEntry       `json:"unlinked_torrents"`
	PermissionIssues  []JSONPermissionEntry    `json:"permission_issues"`
}

// JSONSummary provides high-level counts
type JSONSummary struct {
	TotalFiles            int    `json:"total_files"`
	HealthyCount          int    `json:"healthy_count"`
	AtRiskCount           int    `json:"at_risk_count"`
	OrphanCount           int    `json:"orphan_count"`
	OrphanedDownloadCount int    `json:"orphaned_download_count"`
	SuspiciousCount       int    `json:"suspicious_count"`
	PermissionErrors      int    `json:"permission_errors"`
	PermissionWarnings    int    `json:"permission_warnings"`
	TotalOrphanSizeBytes  int64  `json:"total_orphan_size_bytes"`
	TotalOrphanSizeHuman  string `json:"total_orphan_size_human"`
}

// JSONFileEntry represents a single file for script processing
type JSONFileEntry struct {
	Path           string `json:"path"`
	Size           int64  `json:"size_bytes"`
	SizeHuman      string `json:"size_human"`
	ModTime        string `json:"modified_at"`
	Age            string `json:"age"`
	Hardlinks      int    `json:"hardlinks"`
	Classification string `json:"classification"`
	Reason         string `json:"reason"`
	ArrSource      string `json:"arr_source,omitempty"`
}

// JSONSuspiciousEntry represents suspicious files
type JSONSuspiciousEntry struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// JSONTorrentEntry represents unlinked torrents
type JSONTorrentEntry struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Size      int64  `json:"size_bytes"`
	SizeHuman string `json:"size_human"`
	Completed string `json:"completed"`
}

// JSONPermissionEntry represents permission issues
type JSONPermissionEntry struct {
	Path     string `json:"path"`
	Issue    string `json:"issue"`
	Severity string `json:"severity"`
	FixHint  string `json:"fix_hint"`
}

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (jf *JSONFormatter) Format(result *analysis.AnalysisResult, cfg *config.Config, duration time.Duration) ([]byte, error) {
	report := JSONReport{
		GeneratedAt:      time.Now().Format(time.RFC3339),
		Duration:         duration.Seconds(),
		ConnectionStatus: result.ConnectionStatus,
	}

	// Build summary
	report.Summary = JSONSummary{
		TotalFiles:            result.Summary.TotalFiles,
		HealthyCount:          result.Summary.HealthyCount,
		AtRiskCount:           result.Summary.AtRiskCount,
		OrphanCount:           result.Summary.OrphanCount,
		OrphanedDownloadCount: result.Summary.OrphanedDownloadCount,
		SuspiciousCount:       result.Summary.SuspiciousCount,
		PermissionErrors:      result.Summary.PermissionErrors,
		PermissionWarnings:    result.Summary.PermissionWarnings,
	}

	// Collect orphaned media
	var orphanTotalSize int64
	orphans := filterByClassification(result.ClassifiedMedia, models.MediaOrphan)
	sort.Slice(orphans, func(i, j int) bool {
		return orphans[i].File.Path < orphans[j].File.Path
	})
	for _, cm := range orphans {
		orphanTotalSize += cm.File.Size
		report.OrphanedMedia = append(report.OrphanedMedia, JSONFileEntry{
			Path:           cm.File.Path,
			Size:           cm.File.Size,
			SizeHuman:      formatBytes(cm.File.Size),
			ModTime:        cm.File.ModTime.Format(time.RFC3339),
			Age:            formatDuration(time.Since(cm.File.ModTime)),
			Hardlinks:      cm.File.HardlinkCount,
			Classification: string(cm.Classification),
			Reason:         cm.Reason,
			ArrSource:      cm.ArrSource,
		})
	}
	report.Summary.TotalOrphanSizeBytes = orphanTotalSize
	report.Summary.TotalOrphanSizeHuman = formatBytes(orphanTotalSize)

	// Collect orphaned downloads
	orphanedDownloads := filterByClassification(result.ClassifiedMedia, models.MediaOrphanedDownload)
	sort.Slice(orphanedDownloads, func(i, j int) bool {
		return orphanedDownloads[i].File.Path < orphanedDownloads[j].File.Path
	})
	for _, cm := range orphanedDownloads {
		report.OrphanedDownloads = append(report.OrphanedDownloads, JSONFileEntry{
			Path:           cm.File.Path,
			Size:           cm.File.Size,
			SizeHuman:      formatBytes(cm.File.Size),
			ModTime:        cm.File.ModTime.Format(time.RFC3339),
			Age:            formatDuration(time.Since(cm.File.ModTime)),
			Hardlinks:      cm.File.HardlinkCount,
			Classification: string(cm.Classification),
			Reason:         cm.Reason,
		})
	}

	// Collect at-risk files
	atRisk := filterByClassification(result.ClassifiedMedia, models.MediaAtRisk)
	sort.Slice(atRisk, func(i, j int) bool {
		return atRisk[i].File.Path < atRisk[j].File.Path
	})
	for _, cm := range atRisk {
		report.AtRisk = append(report.AtRisk, JSONFileEntry{
			Path:           cm.File.Path,
			Size:           cm.File.Size,
			SizeHuman:      formatBytes(cm.File.Size),
			ModTime:        cm.File.ModTime.Format(time.RFC3339),
			Age:            formatDuration(time.Since(cm.File.ModTime)),
			Hardlinks:      cm.File.HardlinkCount,
			Classification: string(cm.Classification),
			Reason:         cm.Reason,
			ArrSource:      cm.ArrSource,
		})
	}

	// Collect suspicious files
	sort.Slice(result.SuspiciousFiles, func(i, j int) bool {
		return result.SuspiciousFiles[i].Path < result.SuspiciousFiles[j].Path
	})
	for _, sf := range result.SuspiciousFiles {
		report.SuspiciousFiles = append(report.SuspiciousFiles, JSONSuspiciousEntry{
			Path:   sf.Path,
			Reason: sf.Reason,
		})
	}

	// Collect unlinked torrents
	sort.Slice(result.UnlinkedTorrents, func(i, j int) bool {
		pathI := filepath.Join(result.UnlinkedTorrents[i].SavePath, result.UnlinkedTorrents[i].Name)
		pathJ := filepath.Join(result.UnlinkedTorrents[j].SavePath, result.UnlinkedTorrents[j].Name)
		return pathI < pathJ
	})
	for _, t := range result.UnlinkedTorrents {
		completed := "unknown"
		if !t.CompletedOn.IsZero() {
			completed = formatDuration(time.Since(t.CompletedOn)) + " ago"
		}
		report.UnlinkedTorrents = append(report.UnlinkedTorrents, JSONTorrentEntry{
			Path:      filepath.Join(t.SavePath, t.Name),
			Name:      t.Name,
			Size:      t.Size,
			SizeHuman: formatBytes(t.Size),
			Completed: completed,
		})
	}

	// Collect permission issues
	for _, issue := range result.PermissionIssues {
		report.PermissionIssues = append(report.PermissionIssues, JSONPermissionEntry{
			Path:     issue.Path,
			Issue:    issue.Issue,
			Severity: issue.Severity,
			FixHint:  issue.FixHint,
		})
	}

	return json.MarshalIndent(report, "", "  ")
}

func (jf *JSONFormatter) WriteToFile(data []byte, reportDir string) (string, error) {
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create report directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02-15-04-05")
	filename := filepath.Join(reportDir, fmt.Sprintf("audit-report-%s.json", timestamp))

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write JSON report: %w", err)
	}

	return filename, nil
}
