package reporting

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jdpx/auditarr/internal/analysis"
	"github.com/jdpx/auditarr/internal/config"
	"github.com/jdpx/auditarr/internal/models"
)

type MarkdownFormatter struct{}

func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

func (mf *MarkdownFormatter) Format(result *analysis.AnalysisResult, cfg *config.Config, duration time.Duration) string {
	var buf bytes.Buffer

	buf.WriteString("# Media Audit Report\n\n")
	buf.WriteString(fmt.Sprintf("**Generated**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("**Duration**: %.1f seconds\n\n", duration.Seconds()))

	buf.WriteString("## Summary\n\n")
	buf.WriteString("| Category | Count | Status | Description |\n")
	buf.WriteString("|----------|-------|--------|-------------|\n")
	buf.WriteString(fmt.Sprintf("| Healthy Media | %d | ✅ | Tracked by Arr and hardlinked to torrent |\n", result.Summary.HealthyCount))
	buf.WriteString(fmt.Sprintf("| At Risk | %d | ⚠️ | Tracked by Arr but NOT hardlinked (no torrent protection) |\n", result.Summary.AtRiskCount))
	buf.WriteString(fmt.Sprintf("| Orphaned | %d | ❌ | Not tracked by Arr (outside grace window) |\n", result.Summary.OrphanCount))
	buf.WriteString(fmt.Sprintf("| Suspicious Files | %d | 🚨 | Suspicious extensions detected |\n", result.Summary.SuspiciousCount))
	buf.WriteString("\n")

	if len(result.ConnectionStatus) > 0 {
		buf.WriteString("## Service Connections\n\n")
		buf.WriteString("| Service | Status | Details |\n")
		buf.WriteString("|---------|--------|---------|\n")
		for _, svc := range result.ConnectionStatus {
			status := "✅ Connected"
			details := "OK"
			if !svc.OK {
				status = "❌ Failed"
				details = svc.Error
			}
			buf.WriteString(fmt.Sprintf("| %s | %s | %s |\n", svc.Name, status, escapeMarkdown(details)))
		}
		buf.WriteString("\n")
	}

	atRisk := filterByClassification(result.ClassifiedMedia, models.MediaAtRisk)
	if len(atRisk) > 0 {
		buf.WriteString("## At Risk Media\n\n")
		buf.WriteString("These files are tracked by Sonarr/Radarr but have no hardlink protection:\n\n")
		buf.WriteString("| Path | Source | Age |\n")
		buf.WriteString("|------|--------|-----|\n")
		for _, cm := range atRisk {
			age := time.Since(cm.File.ModTime)
			buf.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", escapeMarkdown(cm.File.Path), cm.ArrSource, formatDuration(age)))
		}
		buf.WriteString("\n")
	}

	orphans := filterByClassification(result.ClassifiedMedia, models.MediaOrphan)
	if len(orphans) > 0 {
		buf.WriteString("## Orphaned Media\n\n")
		buf.WriteString("Files not tracked by any Arr service:\n\n")
		buf.WriteString("| Path | Age |\n")
		buf.WriteString("|------|-----|\n")
		for _, cm := range orphans {
			age := time.Since(cm.File.ModTime)
			buf.WriteString(fmt.Sprintf("| `%s` | %s |\n", escapeMarkdown(cm.File.Path), formatDuration(age)))
		}
		buf.WriteString("\n")
	}

	if len(result.SuspiciousFiles) > 0 {
		buf.WriteString("## Suspicious Files\n\n")
		buf.WriteString("| Path | Reason |\n")
		buf.WriteString("|------|--------|\n")
		for _, sf := range result.SuspiciousFiles {
			buf.WriteString(fmt.Sprintf("| `%s` | %s |\n", escapeMarkdown(sf.Path), sf.Reason))
		}
		buf.WriteString("\n")
	}

	if len(result.UnlinkedTorrents) > 0 {
		buf.WriteString("## Unlinked Torrents\n\n")
		buf.WriteString("Completed torrents with no matching media:\n\n")
		buf.WriteString("| Torrent Name | Save Path | Completed |\n")
		buf.WriteString("|--------------|-----------|-----------|\n")
		for _, t := range result.UnlinkedTorrents {
			completed := "unknown"
			if !t.CompletedOn.IsZero() {
				completed = formatDuration(time.Since(t.CompletedOn)) + " ago"
			}
			buf.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n", escapeMarkdown(t.Name), escapeMarkdown(t.SavePath), completed))
		}
		buf.WriteString("\n")
	}

	buf.WriteString("## Configuration\n\n")
	buf.WriteString(fmt.Sprintf("- Sonarr Grace: %d hours\n", cfg.Sonarr.GraceHours))
	buf.WriteString(fmt.Sprintf("- Radarr Grace: %d hours\n", cfg.Radarr.GraceHours))
	buf.WriteString(fmt.Sprintf("- qBittorrent Grace: %d hours\n", cfg.Qbittorrent.GraceHours))

	return buf.String()
}

func (mf *MarkdownFormatter) WriteToFile(content, reportDir string) (string, error) {
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create report directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02-15-04-05")
	filename := filepath.Join(reportDir, fmt.Sprintf("audit-report-%s.md", timestamp))

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return filename, nil
}

func filterByClassification(classified []models.ClassifiedMedia, class models.MediaClassification) []models.ClassifiedMedia {
	var result []models.ClassifiedMedia
	for _, cm := range classified {
		if cm.Classification == class {
			result = append(result, cm)
		}
	}
	return result
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "\\`")
	return s
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
