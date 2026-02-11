package reporting

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
		buf.WriteString("Connection status of all configured Arr services and download clients:\n\n")
		buf.WriteString("- Verifies API connectivity and authentication\n")
		buf.WriteString("- Checks if services are reachable and responding to health checks\n")
		buf.WriteString("- Reports any connection errors or authentication failures\n\n")
		buf.WriteString("| Service | Status | Details |\n")
		buf.WriteString("|---------|--------|---------|\n")
		sort.Slice(result.ConnectionStatus, func(i, j int) bool {
			return result.ConnectionStatus[i].Name < result.ConnectionStatus[j].Name
		})
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
		buf.WriteString("Files tracked by Sonarr/Radarr but not hardlinked to torrent downloads:\n\n")
		buf.WriteString("**What this means**: These files are known to your Arr services but lack the hardlink protection that normally links them to torrent data. This could happen if:\n\n")
		buf.WriteString("- The import process copied the file instead of creating a hardlink\n")
		buf.WriteString("- The torrent was removed from qBittorrent\n")
		buf.WriteString("- The file system no longer shows the expected link count\n\n")
		buf.WriteString("**Risk**: If the original torrent is removed, these files could be lost if they're not backed up elsewhere.\n\n")
		buf.WriteString("| Path | Source | Age |\n")
		buf.WriteString("|------|--------|-----|\n")
		sort.Slice(atRisk, func(i, j int) bool {
			return atRisk[i].File.Path < atRisk[j].File.Path
		})
		for _, cm := range atRisk {
			age := time.Since(cm.File.ModTime)
			buf.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", escapeMarkdown(cm.File.Path), cm.ArrSource, formatDuration(age)))
		}
		buf.WriteString("\n")
	}

	orphans := filterByClassification(result.ClassifiedMedia, models.MediaOrphan)
	if len(orphans) > 0 {
		buf.WriteString("## Orphaned Media\n\n")
		buf.WriteString("Media files found on disk that are not tracked by Sonarr or Radarr:\n\n")
		buf.WriteString("**What this checks**: Compares filesystem contents against Sonarr/Radarr API to find files that exist in your media directories but aren't registered in the Arr databases.\n\n")
		buf.WriteString("**Why this matters**: Orphaned files consume disk space but aren't managed by your Arr services. They could be:\n\n")
		buf.WriteString("- Leftovers from manual imports\n")
		buf.WriteString("- Files imported outside the grace window\n")
		buf.WriteString("- Media that was deleted from Sonarr/Radarr but not from disk\n")
		buf.WriteString("- Test files or incomplete imports\n\n")
		buf.WriteString("**Grace window**: Files newer than the configured grace hours are excluded to avoid false positives during active imports.\n\n")
		buf.WriteString("| Path | Age |\n")
		buf.WriteString("|------|-----|\n")
		sort.Slice(orphans, func(i, j int) bool {
			return orphans[i].File.Path < orphans[j].File.Path
		})
		for _, cm := range orphans {
			age := time.Since(cm.File.ModTime)
			buf.WriteString(fmt.Sprintf("| `%s` | %s |\n", escapeMarkdown(cm.File.Path), formatDuration(age)))
		}
		buf.WriteString("\n")
	}

	if len(result.SuspiciousFiles) > 0 {
		buf.WriteString("## Suspicious Files\n\n")
		buf.WriteString("Files with potentially problematic extensions or characteristics:\n\n")
		buf.WriteString("**What this looks for**: Unusual file types that may indicate:\n\n")
		buf.WriteString("- Malware or suspicious executables (.exe, .bat, .scr, etc.)\n")
		buf.WriteString("- Incomplete downloads (.part, .crdownload, .tmp, etc.)\n")
		buf.WriteString("- Suspicious archives or scripts that shouldn't be in media folders\n")
		buf.WriteString("- Files with double extensions that could be malware\n\n")
		buf.WriteString("**Action**: Review these files manually to determine if they should be removed.\n\n")
		buf.WriteString("| Path | Reason |\n")
		buf.WriteString("|------|--------|\n")
		sort.Slice(result.SuspiciousFiles, func(i, j int) bool {
			return result.SuspiciousFiles[i].Path < result.SuspiciousFiles[j].Path
		})
		for _, sf := range result.SuspiciousFiles {
			buf.WriteString(fmt.Sprintf("| `%s` | %s |\n", escapeMarkdown(sf.Path), sf.Reason))
		}
		buf.WriteString("\n")
	}

	if len(result.UnlinkedTorrents) > 0 {
		buf.WriteString("## Unlinked Torrents\n\n")
		buf.WriteString("Completed torrents with no matching media:\n\n")
		buf.WriteString("**What this checks**: Torrents marked as completed in qBittorrent that have no corresponding hardlinked files in your media directories.\n\n")
		buf.WriteString("**Why this matters**: These torrents are consuming disk space in your download directory but aren't properly imported into your media library. The torrent files exist at the location below but aren't linked to Arr-managed media.\n\n")
		buf.WriteString("| Full Path | Completed |\n")
		buf.WriteString("|-----------|-----------|\n")
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
			fullPath := filepath.Join(t.SavePath, t.Name)
			buf.WriteString(fmt.Sprintf("| `%s` | %s |\n", escapeMarkdown(fullPath), completed))
		}
		buf.WriteString("\n")
	}

	buf.WriteString("## Configuration\n\n")
	buf.WriteString(fmt.Sprintf("- Sonarr Grace: %d hours\n", cfg.Sonarr.GraceHours))
	buf.WriteString(fmt.Sprintf("- Radarr Grace: %d hours\n", cfg.Radarr.GraceHours))
	buf.WriteString(fmt.Sprintf("- qBittorrent Grace: %d hours\n", cfg.Qbittorrent.GraceHours))
	buf.WriteString(fmt.Sprintf("- Media Root: `%s`\n", cfg.Paths.MediaRoot))

	if len(cfg.PathMappings) > 0 {
		buf.WriteString("\n### Path Mappings\n\n")
		buf.WriteString("| API Path | Filesystem Path |\n")
		buf.WriteString("|----------|----------------|\n")
		for apiPath, fsPath := range cfg.PathMappings {
			buf.WriteString(fmt.Sprintf("| `%s` | `%s` |\n", apiPath, fsPath))
		}
		buf.WriteString("\n")
	}

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
