package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jdpx/auditarr/internal/models"
	"github.com/jdpx/auditarr/internal/utils"
)

type AnalysisResult struct {
	ClassifiedMedia  []models.ClassifiedMedia
	SuspiciousFiles  []models.SuspiciousFile
	UnlinkedTorrents []models.Torrent
	PermissionIssues []models.PermissionIssue
	Summary          SummaryStats
	ConnectionStatus []ServiceStatus
}

type ServiceStatus struct {
	Name    string
	Enabled bool
	OK      bool
	Error   string
}

type SummaryStats struct {
	TotalFiles         int
	HealthyCount       int
	AtRiskCount        int
	OrphanCount        int
	SuspiciousCount    int
	PermissionErrors   int
	PermissionWarnings int
	Duration           time.Duration
}

type Engine struct {
	sonarrGraceHours      int
	radarrGraceHours      int
	qbittorrentGraceHours int
	suspiciousExtensions  []string
	flagArchives          bool
	permissionsEnabled    bool
	expectedGroupGID      int
	allowedUIDs           []int
	sgidPaths             []string
	skipPaths             []string
	nonstandardSeverity   string
	pathMappings          map[string]string
}

func NewEngine(
	sonarrGrace, radarrGrace, qbGrace int,
	suspiciousExts []string,
	flagArchives bool,
	permEnabled bool,
	permGroupGID int,
	permAllowedUIDs []int,
	permSGIDPaths []string,
	permSkipPaths []string,
	permNonstandardSeverity string,
	pathMappings map[string]string,
) *Engine {
	return &Engine{
		sonarrGraceHours:      sonarrGrace,
		radarrGraceHours:      radarrGrace,
		qbittorrentGraceHours: qbGrace,
		suspiciousExtensions:  suspiciousExts,
		flagArchives:          flagArchives,
		permissionsEnabled:    permEnabled,
		expectedGroupGID:      permGroupGID,
		allowedUIDs:           permAllowedUIDs,
		sgidPaths:             permSGIDPaths,
		skipPaths:             permSkipPaths,
		nonstandardSeverity:   permNonstandardSeverity,
		pathMappings:          pathMappings,
	}
}

func (e *Engine) Analyze(
	mediaFiles []models.MediaFile,
	sonarrFiles []models.ArrFile,
	radarrFiles []models.ArrFile,
	torrents []models.Torrent,
	permissions []models.FilePermissions,
) *AnalysisResult {
	result := &AnalysisResult{}

	arrLookup := e.buildArrLookup(sonarrFiles, radarrFiles)

	for i, media := range mediaFiles {
		if shouldSkip(media.Path, e.skipPaths) {
			continue
		}

		lookupKey := e.normalizePath(media.Path)
		arrFile := arrLookup[lookupKey]
		if i == 0 {
			fmt.Fprintf(os.Stderr, "DEBUG: First media path: %s lookup=%s found=%v\n",
				media.Path, lookupKey, arrFile != nil)
		}
		graceHours := e.getGraceHours(arrFile)

		classification, shouldInclude := ClassifyMedia(media, arrFile, graceHours)
		if !shouldInclude {
			continue
		}

		if classification == models.MediaOrphan && utils.IsSubtitleFile(media.Path) {
			continue
		}

		arrSource := ""
		if arrFile != nil && arrFile.SeriesID > 0 {
			arrSource = "sonarr"
		} else if arrFile != nil && arrFile.MovieID > 0 {
			arrSource = "radarr"
		}

		result.ClassifiedMedia = append(result.ClassifiedMedia, models.ClassifiedMedia{
			File:           media,
			KnownToArr:     arrFile != nil && arrFile.IsKnown(),
			ArrSource:      arrSource,
			Classification: classification,
			Reason:         getReason(classification, media, arrFile),
		})

		if classification == models.MediaHealthy {
			result.Summary.HealthyCount++
		} else if classification == models.MediaAtRisk {
			result.Summary.AtRiskCount++
		} else if classification == models.MediaOrphan {
			result.Summary.OrphanCount++
		}
		result.Summary.TotalFiles++

		if isSuspicious, reason := models.IsSuspicious(media.Path, e.suspiciousExtensions, e.flagArchives); isSuspicious {
			result.SuspiciousFiles = append(result.SuspiciousFiles, models.SuspiciousFile{
				Path:   media.Path,
				Reason: reason,
			})
			result.Summary.SuspiciousCount++
		}
	}

	for _, t := range torrents {
		if t.State == models.StateCompleted && !t.WithinGraceWindow(e.qbittorrentGraceHours) {
			if !e.hasMatchingMediaFile(t, arrLookup) {
				result.UnlinkedTorrents = append(result.UnlinkedTorrents, t)
			}
		}
	}

	if e.permissionsEnabled {
		for _, perm := range permissions {
			if shouldSkip(perm.Path, e.skipPaths) {
				continue
			}
			issues := e.auditPermissions(perm)
			result.PermissionIssues = append(result.PermissionIssues, issues...)
			for _, issue := range issues {
				if issue.Severity == "error" {
					result.Summary.PermissionErrors++
				} else {
					result.Summary.PermissionWarnings++
				}
			}
		}
	}

	return result
}

func (e *Engine) getGraceHours(arrFile *models.ArrFile) int {
	if arrFile == nil {
		return 0
	}
	if arrFile.SeriesID > 0 {
		return e.sonarrGraceHours
	}
	if arrFile.MovieID > 0 {
		return e.radarrGraceHours
	}
	return 0
}

func (e *Engine) buildArrLookup(sonarrFiles, radarrFiles []models.ArrFile) map[string]*models.ArrFile {
	lookup := make(map[string]*models.ArrFile)
	for i := range sonarrFiles {
		normalizedPath := utils.NormalizePath(sonarrFiles[i].Path, e.pathMappings)
		lookup[e.normalizePath(normalizedPath)] = &sonarrFiles[i]
	}
	for i := range radarrFiles {
		normalizedPath := utils.NormalizePath(radarrFiles[i].Path, e.pathMappings)
		lookup[e.normalizePath(normalizedPath)] = &radarrFiles[i]
		if i == 0 {
			fmt.Fprintf(os.Stderr, "DEBUG: First Radarr path: orig=%s mapped=%s lookup=%s\n",
				radarrFiles[i].Path, normalizedPath, e.normalizePath(normalizedPath))
		}
	}
	return lookup
}

func (e *Engine) hasMatchingMediaFile(t models.Torrent, mediaLookup map[string]*models.ArrFile) bool {
	for _, f := range t.Files {
		fullPath := filepath.Join(t.SavePath, f)

		hardlinked, nlink, err := isHardlinkedWithDetails(fullPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DEBUG: torrent=%s file=%s path=%s stat_error=%v\n", t.Name, f, fullPath, err)
		} else {
			fmt.Fprintf(os.Stderr, "DEBUG: torrent=%s file=%s path=%s hardlinked=%v nlink=%d\n", t.Name, f, fullPath, hardlinked, nlink)
		}
		if hardlinked {
			return true
		}

		normalizedPath := utils.NormalizePath(fullPath, e.pathMappings)
		if _, exists := mediaLookup[e.normalizePath(normalizedPath)]; exists {
			return true
		}
	}
	return false
}

func isHardlinkedWithDetails(path string) (bool, uint64, error) {
	var stat syscall.Stat_t
	err := syscall.Stat(path, &stat)
	if err != nil {
		return false, 0, err
	}
	return stat.Nlink > 1, uint64(stat.Nlink), nil
}

func (e *Engine) normalizePath(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

func shouldSkip(path string, skipPaths []string) bool {
	for _, skip := range skipPaths {
		if strings.HasPrefix(path, skip) {
			return true
		}
	}
	return false
}

func getReason(class models.MediaClassification, media models.MediaFile, arrFile *models.ArrFile) string {
	switch class {
	case models.MediaHealthy:
		return "Tracked by Arr and hardlinked to torrent"
	case models.MediaAtRisk:
		return "Tracked by Arr but NOT hardlinked (no torrent protection)"
	case models.MediaOrphan:
		return "Not tracked by Arr (outside grace window)"
	default:
		return "Unknown classification"
	}
}

func (e *Engine) auditPermissions(file models.FilePermissions) []models.PermissionIssue {
	if IsMetadataFile(file.Path) {
		return nil
	}

	var issues []models.PermissionIssue

	if !e.isValidOwner(file.OwnerUID) {
		if file.IsDirectory && file.OwnerUID == 0 {
			issues = append(issues, models.PermissionIssue{
				Path:     file.Path,
				Issue:    "wrong_owner",
				Severity: "warning",
				FixHint:  fmt.Sprintf("Directory owned by root (UID 0), expected one of: %v", e.allowedUIDs),
			})
		} else {
			issues = append(issues, models.PermissionIssue{
				Path:     file.Path,
				Issue:    "wrong_owner",
				Severity: "error",
				FixHint:  fmt.Sprintf("File owned by UID %d, expected one of: %v", file.OwnerUID, e.allowedUIDs),
			})
		}
	}

	if file.GroupGID != e.expectedGroupGID {
		issues = append(issues, models.PermissionIssue{
			Path:     file.Path,
			Issue:    "wrong_group",
			Severity: "error",
			FixHint:  fmt.Sprintf("File group is GID %d, expected %d", file.GroupGID, e.expectedGroupGID),
		})
	}

	if !file.GroupWritable() {
		issues = append(issues, models.PermissionIssue{
			Path:     file.Path,
			Issue:    "not_group_writable",
			Severity: "warning",
			FixHint:  "Group cannot write to file",
		})
	}

	if file.IsDirectory && e.shouldHaveSGID(file.Path) && !file.HasSGID() {
		issues = append(issues, models.PermissionIssue{
			Path:     file.Path,
			Issue:    "missing_sgid",
			Severity: "warning",
			FixHint:  "Directory missing SGID bit (new files won't inherit group)",
		})
	}

	return issues
}

func (e *Engine) isValidOwner(uid int) bool {
	for _, allowed := range e.allowedUIDs {
		if uid == allowed {
			return true
		}
	}
	return false
}

func (e *Engine) shouldHaveSGID(path string) bool {
	for _, sgidPath := range e.sgidPaths {
		if strings.HasPrefix(path, sgidPath) {
			return true
		}
	}
	return false
}
