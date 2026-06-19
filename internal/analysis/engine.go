package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jdpx/auditarr/internal/models"
	"github.com/jdpx/auditarr/internal/utils"
)

type AnalysisResult struct {
	ClassifiedMedia     []models.ClassifiedMedia
	SuspiciousFiles     []models.SuspiciousFile
	UnlinkedTorrents    []models.Torrent
	PermissionIssues    []models.PermissionIssue
	OrphanedDirectories []OrphanedDirectory
	Summary             SummaryStats
	ConnectionStatus    []ServiceStatus
}

type OrphanedDirectory struct {
	Path          string
	OrphanedCount int
	TotalCount    int
	TotalSize     int64
	FullyOrphaned bool
}

type ServiceStatus struct {
	Name    string
	Enabled bool
	OK      bool
	Error   string
}

type SummaryStats struct {
	TotalFiles            int
	HealthyCount          int
	AtRiskCount           int
	OrphanCount           int
	OrphanedDownloadCount int
	HiddenFileCount       int
	LostAndFoundCount     int
	SuspiciousCount       int
	PermissionErrors      int
	PermissionWarnings    int
	TotalLogicalSize      int64
	TotalBlockSize        int64
	Duration              time.Duration
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
	torrentRoot           string
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
	torrentRoot string,
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
		torrentRoot:           torrentRoot,
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
	torrentFileIndex := e.buildTorrentFileIndex(torrents)

	for _, media := range mediaFiles {
		if shouldSkip(media.Path, e.skipPaths) {
			continue
		}

		// Track disk usage stats for all files
		result.Summary.TotalLogicalSize += media.Size
		result.Summary.TotalBlockSize += media.BlockSize

		lookupKey := e.normalizePath(media.Path)
		arrFile := arrLookup[lookupKey]
		graceHours := e.getGraceHours(arrFile, media.Source)

		var classification models.MediaClassification
		var shouldInclude bool

		switch media.Source {
		case models.MediaSourceExtra:
			classification, shouldInclude = ClassifyExtraFile(media)
		case models.MediaSourceTorrent:
			inActiveTorrent := e.belongsToActiveTorrent(media.Path, torrentFileIndex)
			classification, shouldInclude = ClassifyTorrentFile(media, arrFile, graceHours, inActiveTorrent)
		default:
			classification, shouldInclude = ClassifyMedia(media, arrFile, graceHours)
		}

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

		switch classification {
		case models.MediaHealthy:
			result.Summary.HealthyCount++
		case models.MediaAtRisk:
			result.Summary.AtRiskCount++
		case models.MediaOrphan:
			result.Summary.OrphanCount++
		case models.MediaOrphanedDownload:
			result.Summary.OrphanedDownloadCount++
		case models.MediaHiddenFile:
			result.Summary.HiddenFileCount++
		case models.MediaLostAndFound:
			result.Summary.LostAndFoundCount++
		}
		result.Summary.TotalFiles++
	}

	// Build directory-level orphan summary
	result.OrphanedDirectories = e.buildOrphanedDirectories(result.ClassifiedMedia)

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

func (e *Engine) getGraceHours(arrFile *models.ArrFile, source models.MediaFileSource) int {
	if arrFile == nil {
		if source == models.MediaSourceTorrent {
			return e.qbittorrentGraceHours
		}
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

// buildTorrentFileIndex indexes every file currently managed by qBittorrent by
// its (lowercased) basename, mapping to the full qBittorrent-side paths. It is
// used to tell whether a scanned torrent-dir file still belongs to a live
// torrent, regardless of how the download client's mount differs from ours.
func (e *Engine) buildTorrentFileIndex(torrents []models.Torrent) map[string][]string {
	idx := make(map[string][]string)
	for _, t := range torrents {
		for _, f := range t.Files {
			full := strings.ToLower(filepath.Clean(filepath.Join(t.SavePath, f)))
			base := strings.ToLower(filepath.Base(f))
			idx[base] = append(idx[base], full)
		}
	}
	return idx
}

// belongsToActiveTorrent reports whether a scanned file (host path) is part of a
// torrent qBittorrent still manages. It matches on the torrent-root-relative
// path suffix, so it is independent of the differing /data mount points between
// qBittorrent and the *arr apps. A match means the file is being seeded or is
// awaiting import — it must not be treated as an orphaned download.
func (e *Engine) belongsToActiveTorrent(hostPath string, idx map[string][]string) bool {
	if e.torrentRoot == "" || len(idx) == 0 {
		return false
	}
	rel, err := filepath.Rel(e.torrentRoot, hostPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	rel = strings.ToLower(filepath.Clean(rel))
	base := strings.ToLower(filepath.Base(hostPath))
	for _, cand := range idx[base] {
		if cand == rel || strings.HasSuffix(cand, "/"+rel) {
			return true
		}
	}
	return false
}

func (e *Engine) hasMatchingMediaFile(t models.Torrent, mediaLookup map[string]*models.ArrFile) bool {
	for _, f := range t.Files {
		fullPath := filepath.Join(t.SavePath, f)

		// Apply path mapping FIRST before checking hardlinks
		normalizedPath := utils.NormalizePath(fullPath, e.pathMappings)

		hardlinked := isHardlinked(normalizedPath)
		if hardlinked {
			return true
		}

		if _, exists := mediaLookup[e.normalizePath(normalizedPath)]; exists {
			return true
		}
	}
	return false
}

func isHardlinked(path string) bool {
	var stat syscall.Stat_t
	err := syscall.Stat(path, &stat)
	if err != nil {
		return false
	}
	return stat.Nlink > 1
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
	case models.MediaOrphanedDownload:
		return "Orphaned download: in torrent dir, not hardlinked, not tracked by Arr"
	case models.MediaHiddenFile:
		return "Hidden file (dot-prefix): likely incomplete download fragment"
	case models.MediaLostAndFound:
		return "Found in extra scan path (e.g. lost+found): filesystem recovery artifact"
	default:
		return "Unknown classification"
	}
}

func (e *Engine) buildOrphanedDirectories(classified []models.ClassifiedMedia) []OrphanedDirectory {
	type dirStats struct {
		orphanedCount int
		totalCount    int
		totalSize     int64
	}

	dirs := make(map[string]*dirStats)

	for _, cm := range classified {
		if cm.File.Source != models.MediaSourceTorrent {
			continue
		}

		dir := filepath.Dir(cm.File.Path)

		if _, exists := dirs[dir]; !exists {
			dirs[dir] = &dirStats{}
		}
		dirs[dir].totalCount++
		dirs[dir].totalSize += cm.File.Size

		if cm.Classification == models.MediaOrphanedDownload || cm.Classification == models.MediaHiddenFile {
			dirs[dir].orphanedCount++
		}
	}

	var result []OrphanedDirectory
	for path, stats := range dirs {
		if stats.orphanedCount == 0 {
			continue
		}
		result = append(result, OrphanedDirectory{
			Path:          path,
			OrphanedCount: stats.orphanedCount,
			TotalCount:    stats.totalCount,
			TotalSize:     stats.totalSize,
			FullyOrphaned: stats.orphanedCount == stats.totalCount,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalSize > result[j].TotalSize
	})

	return result
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
