# Media Audit Service - Implementation Plan

## Overview

A non-destructive, stateless audit tool for Arr-managed media libraries. Provides visibility into media health without any automated remediation.

**Repository**: `github.com/jdpx/auditarr`
**Binary Name**: `auditarr`
**Report Location**: `/var/lib/auditarr/reports/`

## Architecture Principles

- **Non-destructive**: Read-only operations on filesystem and APIs
- **Stateless**: No database, no historical state between runs
- **Simple**: Single Go binary, minimal dependencies
- **Extensible**: Designed for future enhancements without complexity now

---

## Phase 1: Foundation (Core Infrastructure)

### Step 1.1: Project Structure

**Directory Layout:**
```
cmd/auditarr/
├── main.go                    # CLI entry point
internal/
├── config/
│   ├── config.go             # TOML configuration structures
│   └── loader.go             # Config file loading
├── collectors/
│   ├── interface.go          # Collector interface definition
│   ├── filesystem.go         # Filesystem walker
│   ├── sonarr.go            # Sonarr API client
│   ├── radarr.go            # Radarr API client
│   └── qbittorrent.go       # qBittorrent API client
├── models/
│   ├── media.go             # Media file representation
│   ├── torrent.go           # Torrent representation
│   └── classification.go    # Classification enum/types
├── analysis/
│   ├── engine.go            # Signal combination logic
│   └── rules.go             # Classification rule implementations
├── reporting/
│   ├── generator.go         # Report generation coordinator
│   ├── markdown.go          # Markdown output formatter
│   └── notification.go        # Discord webhook sender
└── utils/
    ├── paths.go             # Path utilities
    └── validators.go        # Input validation
```

**Checkpoints:**
- [ ] Initialize Go module with proper module path (e.g., `go mod init github.com/jdpx/auditarr`)
- [ ] Create directory structure as shown above
- [ ] Define go.mod with minimal dependencies:
  - `github.com/BurntSushi/toml` (TOML parsing)
  - Standard library only for rest (no external HTTP clients needed)
- [ ] Add .gitignore for Go projects (binaries, vendor/, etc.)

### Step 1.2: Configuration Layer

**Implementation:**

```go
// internal/config/config.go
package config

type Config struct {
    Paths       PathsConfig       `toml:"paths"`
    Sonarr      ArrConfig         `toml:"sonarr"`
    Radarr      ArrConfig         `toml:"radarr"`
    Qbittorrent QBConfig          `toml:"qbittorrent"`
    Notifications NotificationConfig `toml:"notifications"`
    Outputs     OutputConfig      `toml:"outputs"`
    Suspicious  SuspiciousConfig  `toml:"suspicious"`
    Permissions PermissionsConfig `toml:"permissions"`
}

type SuspiciousConfig struct {
    Extensions   []string `toml:"extensions"`
    FlagArchives bool     `toml:"flag_archives"`
}

type PermissionsConfig struct {
    Enabled             bool     `toml:"enabled"`
    GroupGID            int      `toml:"group_gid"`
    AllowedUIDs         []int    `toml:"allowed_uids"`
    SGIDPaths           []string `toml:"sgid_paths"`
    SkipPaths           []string `toml:"skip_paths"`
    NonstandardSeverity string   `toml:"nonstandard_severity"`
}

type PathsConfig struct {
    MediaRoot   string `toml:"media_root"`
    TorrentRoot string `toml:"torrent_root"`
}

type ArrConfig struct {
    URL         string `toml:"url"`
    APIKey      string `toml:"api_key"`
    GraceHours  int    `toml:"grace_hours"`
}

type QBConfig struct {
    URL         string `toml:"url"`
    Username    string `toml:"username"`
    Password    string `toml:"password"`
    GraceHours  int    `toml:"grace_hours"`
}

type NotificationConfig struct {
    DiscordWebhook string `toml:"discord_webhook"`
}

type OutputConfig struct {
    ReportDir string `toml:"report_dir"`
}
```

**Sample Configuration File:**

```toml
# Media Audit Configuration
# Note: Secrets (API keys, passwords, webhooks) stored in plaintext per operational decision

[paths]
media_root = "/mnt/media-arr/media"
torrent_root = "/mnt/media-arr/torrents"

[sonarr]
url = "http://localhost:8989"
api_key = "your-api-key-here"
grace_hours = 48

[radarr]
url = "http://localhost:7878"
api_key = "your-api-key-here"
grace_hours = 48

[qbittorrent]
url = "http://localhost:8080"
username = "admin"
password = "your-password-here"
grace_hours = 24

[notifications]
discord_webhook = "https://discord.com/api/webhooks/..."

[outputs]
# Platform-specific defaults applied if not specified:
# - Linux/NixOS: /var/lib/auditarr/reports
# - macOS: ~/Library/Application Support/auditarr/reports
# - Other: ./reports
report_dir = "/var/lib/auditarr/reports"

[suspicious]
# Optional: Override default suspicious extensions
# extensions = ["exe", "msi", "bat", "zip", "rar"]
# flag_archives = true  # Flag zip/rar/7z in media paths

[permissions]
# Permission auditing for arr_stack setup (matches NixOS configuration)
enabled = true

# Expected group GID (arr_stack = 1000 in your NixOS setup)
group_gid = 1000

# Allowed UIDs that can own files (from users.nix)
# sonarr=1001, radarr=1002, prowlarr=1003, qbittorrent=1004, bazarr=1005, etc.
allowed_uids = [1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008]

# Paths that should have SGID bit set (from storage.nix tmpfiles rules)
sgid_paths = [
    "/mnt/media-arr/media",
    "/mnt/media-arr/media/tv",
    "/mnt/media-arr/media/movies",
    "/mnt/media-arr/media/music",
]

# Paths to skip permission checks (optional)
# skip_paths = ["/mnt/media-arr/torrents"]

# Severity for nonstandard permissions (info, warning, error)
nonstandard_severity = "warning"
```

**Features:**
- TOML parsing with validation
- Sensible defaults for grace windows (48h Arr, 24h torrents)
- URL validation for API endpoints
- Platform-specific default paths for report_dir
- **Security Note**: All secrets stored in plaintext as per operational decision. Config file should be readable only by root/auditarr user (chmod 600).

**Checkpoints:**
- [ ] Define all config structures
- [ ] Implement TOML loading with github.com/BurntSushi/toml
- [ ] Add validation logic (required fields, URL format)
- [ ] Create example configuration file
- [ ] Unit tests for config loading and validation

### Step 1.3: Core Models

**Implementation:**

```go
// internal/models/media.go
package models

import "time"

type MediaFile struct {
    Path         string
    Size         int64
    ModTime      time.Time
    HardlinkCount int
    IsHardlinked bool  // Computed: HardlinkCount > 1
}

func (m *MediaFile) WithinGraceWindow(hours int) bool {
    if hours <= 0 {
        return false  // No grace window means always outside
    }
    // Handle future timestamps (clock skew) - treat as within grace
    // time.Since returns negative for future times, so we check both directions
    elapsed := time.Since(m.ModTime)
    if elapsed < 0 {
        return true  // Future timestamp, treat as within grace to be safe
    }
    return elapsed < time.Duration(hours)*time.Hour
}
```

```go
// internal/models/torrent.go
package models

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
    Files       []string  // Relative paths within torrent
}

func (t *Torrent) IsActive() bool {
    return t.State == StateDownloading || t.State == StateChecking
}

func (t *Torrent) WithinGraceWindow(hours int) bool {
    if hours <= 0 {
        return false  // No grace window means always outside
    }
    // Incomplete torrents (zero time) are always within grace
    if t.CompletedOn.IsZero() {
        return true
    }
    // Handle future timestamps (clock skew) - treat as within grace
    elapsed := time.Since(t.CompletedOn)
    if elapsed < 0 {
        return true  // Future timestamp, treat as within grace to be safe
    }
    return elapsed < time.Duration(hours)*time.Hour
}
```

```go
// internal/models/classification.go
package models

type MediaClassification string

const (
    MediaHealthy MediaClassification = "healthy"
    MediaAtRisk  MediaClassification = "at_risk"
    MediaOrphan  MediaClassification = "orphan"
    // Note: MediaPendingImport intentionally NOT defined in v1
    // Files within grace window are excluded entirely from reports
)

type ClassifiedMedia struct {
    File           MediaFile
    KnownToArr     bool
    ArrSource       string  // "sonarr", "radarr", or ""
    Classification  MediaClassification
    Reason         string  // Human-readable explanation
}
```

**Checkpoints:**
- [ ] Define MediaFile with filesystem attributes
- [ ] Define Torrent with state management
- [ ] Define classification types
- [ ] Add helper methods for grace window calculations
- [ ] Unit tests for model behavior

---

## Phase 2: Data Collection

### Step 2.1: Filesystem Collector

**Responsibilities:**
- Walk media and torrent directories
- Collect file metadata (path, size, mtime, hardlink count)
- No file content reading
- Handle permission errors gracefully

**Implementation Details:**

```go
// internal/collectors/filesystem.go
package collectors

type FilesystemCollector struct {
    mediaRoot   string
    torrentRoot string
}

func (fc *FilesystemCollector) Collect(ctx context.Context) ([]models.MediaFile, error) {
    // Walk media_root only, collect MediaFile structs
    // torrent_root is NOT walked - torrent info comes from qBittorrent API collector
    // This ensures we only scan media files, not raw torrent payloads
    // Use syscall.Stat_t for hardlink count on Linux
}
```

**Key Considerations:**
- Use `filepath.WalkDir` for efficiency
- Extract hardlink count via `syscall.Stat_t.Nlink`
- Handle symlinks appropriately (follow or skip based on config)
- Skip hidden files/directories
- Progress logging for large libraries

**Checkpoints:**
- [ ] Implement directory walking
- [ ] Extract hardlink count from inodes
- [ ] Handle symlink resolution
- [ ] Add context cancellation support
- [ ] Error handling for permission denied
- [ ] Integration test with sample directory structure

### Step 2.2: Sonarr API Collector

**API Endpoints Required:**
- `GET /api/v3/series` - List all series
- `GET /api/v3/episode?seriesId={id}` - Episodes per series
- `GET /api/v3/episodefile?seriesId={id}` - Episode files per series

**Implementation:**

```go
// internal/collectors/sonarr.go
package collectors

type SonarrCollector struct {
    client  *http.Client
    baseURL string
    apiKey  string
}

func (sc *SonarrCollector) Collect(ctx context.Context) ([]models.ArrFile, error) {
    // Fetch all series
    // For each series, fetch episodes and episode files
    // Build ArrFile structs with path information
}

type ArrFile struct {
    Path       string
    SeriesID   int
    EpisodeID  int
    Monitored  bool  // Unmonitored is a valid end-state, treated as "known"
    ImportDate time.Time
}

// IsKnown returns true for both monitored and unmonitored items
// Unmonitored indicates a completed/ended series, which is valid
// A file is "known" if it exists in Arr (has valid path), regardless of monitored state
func (af *ArrFile) IsKnown() bool {
    return af != nil && af.Path != "" && af.SeriesID > 0  // or MovieID > 0 for Radarr
}
```

**Checkpoints:**
- [ ] Define Sonarr API client structure
- [ ] Implement series fetching
- [ ] Implement episode file fetching
- [ ] Handle pagination if needed
- [ ] Map API responses to internal models
- [ ] Add API authentication (X-Api-Key header)
- [ ] Error handling for connection failures
- [ ] Integration test against real Sonarr instance

### Step 2.3: Radarr API Collector

**API Endpoints Required:**
- `GET /api/v3/movie` - List all movies
- `GET /api/v3/moviefile?movieId={id}` - Movie files

**Implementation:**

Similar structure to Sonarr collector, adapting to Radarr's API structure.

**Checkpoints:**
- [ ] Implement Radarr API client
- [ ] Fetch movies and movie files
- [ ] Map to internal ArrFile model
- [ ] Integration test against real Radarr instance

### Step 2.4: qBittorrent API Collector

**API Endpoints Required:**
- `POST /api/v2/auth/login` - Authentication
- `GET /api/v2/torrents/info` - List torrents
- `GET /api/v2/torrents/files?hash={hash}` - Files in torrent

**Implementation:**

```go
// internal/collectors/qbittorrent.go
package collectors

type QBCollector struct {
    client   *http.Client
    baseURL  string
    username string
    password string
    cookie   string  // Session cookie after auth
}

func (qbc *QBCollector) Authenticate(ctx context.Context) error {
    // POST to /api/v2/auth/login
    // Store cookie for subsequent requests
}

func (qbc *QBCollector) Collect(ctx context.Context) ([]models.Torrent, error) {
    // Fetch torrent list with states and save paths
    // For each torrent, fetch file list
    // Build Torrent structs
}
```

**Checkpoints:**
- [ ] Implement authentication flow
- [ ] Implement torrent listing
- [ ] Fetch file lists per torrent
- [ ] Map torrent states to internal enum
- [ ] Handle session expiration/re-auth
- [ ] Integration test against real qBittorrent instance

---

## Phase 3: Analysis Engine

### Step 3.1: Signal Combination Logic

**Core Algorithm:**

```go
// internal/analysis/engine.go
package analysis

type AnalysisEngine struct {
    config *config.Config
}

func (ae *AnalysisEngine) Analyze(
    mediaFiles []models.MediaFile,
    arrFiles []models.ArrFile,  // Combined from Sonarr + Radarr
    torrents []models.Torrent,
) (*AnalysisResult, error) {
    // Create lookup maps for O(1) access
    // Match media files to Arr files by path
    // Match media files to torrents via hardlink detection
    // Apply classification rules
    // Return structured results
}

type AnalysisResult struct {
    ClassifiedMedia []models.ClassifiedMedia
    SuspiciousFiles []models.SuspiciousFile
    UnlinkedTorrents []models.Torrent  // Completed torrents not hardlinked
    Summary         SummaryStats
}
```

**Checkpoints:**
- [ ] Implement path matching algorithm
- [ ] Build lookup maps for efficient access
- [ ] Handle path normalization (symlinks, relative vs absolute)
- [ ] Unit tests for signal combination

### Step 3.2: Classification Rules

**Media Classification Logic:**

```go
// internal/analysis/rules.go
package analysis

// ClassifyMedia determines the classification of a media file based on Arr knowledge
// and hardlink status. Files within grace window are excluded entirely (not classified).
// Returns (classification, shouldInclude) - shouldInclude is false for files within grace.
func ClassifyMedia(
    media models.MediaFile,
    arrFile *models.ArrFile,  // nil if unknown to Arr
    graceHours int,
) (models.MediaClassification, bool) {
    // Validate graceHours - must be positive
    if graceHours <= 0 {
        // Invalid grace window, treat all files as outside grace
        // This ensures we don't silently skip everything
        graceHours = 0  // WithinGraceWindow will return false for this
    }
    
    // Files within grace window are excluded entirely from reporting
    // This avoids false positives during active imports
    if media.WithinGraceWindow(graceHours) {
        return "", false
    }
    
    if arrFile == nil {
        // Unknown to Arr and outside grace window
        return models.MediaOrphan, true
    }
    
    // Known to Arr and outside grace window
    if media.IsHardlinked {
        return models.MediaHealthy, true
    }
    
    // Known but not hardlinked
    return models.MediaAtRisk, true
}

// Note: MediaPendingImport classification is intentionally NOT used in v1.
// Files within grace window are excluded entirely to avoid false positives.
// Only three classifications are reported: Healthy, At Risk, Orphan.
```

**Implementation Decision:**

For files within grace window (regardless of Arr knowledge):
- **Exclude entirely from report** to avoid false positives during active imports
- This applies to both "unknown to Arr" files and "known to Arr" files
- Only files **outside** the grace window are classified and reported

**Classification Logic:**
1. Check grace window first - if within, skip entirely
2. If outside grace and unknown to Arr → Orphan
3. If outside grace, known to Arr, and hardlinked → Healthy  
4. If outside grace, known to Arr, and not hardlinked → At Risk

**Note**: MediaPendingImport is not used in v1. This simplifies the report and avoids confusion.

**Checkpoints:**
- [ ] Implement healthy classification
- [ ] Implement at risk classification (files known to Arr but not hardlinked)
- [ ] Implement orphan classification (files not known to Arr)
- [ ] Handle unmonitored items correctly (valid state, not flagged as orphan)
- [ ] Validate graceHours > 0 in ClassifyMedia()
- [ ] Unit tests for all classification paths

### Step 3.3: Suspicious File Detection

**Implementation:**

```go
// internal/analysis/suspicious.go
package analysis

import (
    "path/filepath"
    "strings"
)

var suspiciousExtensions = []string{
    ".exe", ".msi", ".bat", ".cmd", ".com", ".scr",
    ".ps1", ".vbs", ".js", ".jar", ".dll", ".sys",
    ".reg", ".lnk", ".pif", ".apk", ".dmg", ".pkg",
    ".iso", ".zip", ".rar", ".7z", ".tar", ".gz",
}

func IsSuspicious(path string) (bool, string) {
    ext := strings.ToLower(filepath.Ext(path))
    
    // Check direct extension
    for _, susExt := range suspiciousExtensions {
        if ext == susExt {
            return true, "suspicious_extension"
        }
    }
    
    // Check for double extensions
    // e.g., "movie.mkv.exe" -> .exe is suspicious
    // "archive.zip" -> .zip flagged based on config
    
    return false, ""
}
```

**Configuration:**

```toml
[suspicious]
extensions = ["exe", "msi", "bat", "zip", "rar"]  # Override defaults
flag_archives = true  # Flag zip/rar/7z in media paths
```

**Checkpoints:**
- [ ] Define default suspicious extensions
- [ ] Implement extension checking
- [ ] Implement double extension detection
- [ ] Add configurable archive flagging
- [ ] Unit tests for detection logic

### Step 3.4: Permission Auditing (NEW)

**Purpose**: Validate file and directory permissions match Trash Guides best practices and your NixOS arr_stack setup.

**Current NixOS Setup Reference:**
```
Group: arr_stack (GID 1000) - shared by all services
Users: sonarr(1001), radarr(1002), qbittorrent(1004), bazarr(1005), etc.

Expected Permissions:
/mnt/media-arr              0775 root:arr_stack
/mnt/media-arr/media        2775 root:arr_stack  (SGID bit)
/mnt/media-arr/media/tv     2775 sonarr:arr_stack (SGID bit)
/mnt/media-arr/media/movies 2775 radarr:arr_stack (SGID bit)
/mnt/media-arr/torrents     0775 qbittorrent:arr_stack

Trash Guides Best Practices:
- UMASK 002 => Files: 664, Directories: 775
- All services share arr_stack group
- SGID on media dirs (new files inherit group)
- Group read+write required for hardlinks
```

**Implementation:**

```go
// internal/models/permissions.go
package models

type PermissionIssue struct {
    Path        string
    CurrentMode uint32
    ExpectedMode uint32
    Owner       int
    Group       int
    Issue       string  // "wrong_owner", "wrong_group", "wrong_permissions", "missing_sgid"
    Severity    string  // "warning", "error"
    FixHint     string  // Human-readable suggestion
}

type FilePermissions struct {
    Path        string
    Mode        uint32  // File mode bits
    OwnerUID    int
    GroupGID    int
    IsDirectory bool
}

func (fp *FilePermissions) ModeString() string {
    // Return "-rwxrwxr-x" or "drwxrwsr-x" format
}

func (fp *FilePermissions) HasSGID() bool {
    return fp.Mode&02000 != 0  // Check SGID bit
}

func (fp *FilePermissions) GroupWritable() bool {
    return fp.Mode&0020 != 0  // Check group write bit
}
```

```go
// internal/analysis/permissions.go
package analysis

type PermissionAuditor struct {
    expectedGroupGID int      // 1000 for arr_stack
    expectedUsers    []int    // UIDs that are allowed (sonarr, radarr, etc.)
    sgidPaths        []string // Paths that should have SGID bit (media/tv, media/movies)
}

func (pa *PermissionAuditor) Audit(file models.FilePermissions) []models.PermissionIssue {
    var issues []models.PermissionIssue
    
    // Check 1: File must be owned by an expected user
    if !pa.isValidOwner(file.OwnerUID) {
        issues = append(issues, models.PermissionIssue{
            Path: file.Path,
            Issue: "wrong_owner",
            Severity: "error",
            FixHint: fmt.Sprintf("File owned by UID %d, expected one of: %v. Run: sudo chown sonarr:arr_stack '%s'", 
                file.OwnerUID, pa.expectedUsers, file.Path),
        })
    }
    
    // Check 2: File must belong to arr_stack group
    if file.GroupGID != pa.expectedGroupGID {
        issues = append(issues, models.PermissionIssue{
            Path: file.Path,
            Issue: "wrong_group",
            Severity: "error", 
            FixHint: fmt.Sprintf("File group is GID %d, expected %d (arr_stack). Run: sudo chgrp arr_stack '%s'",
                file.GroupGID, pa.expectedGroupGID, file.Path),
        })
    }
    
    // Check 3: Group must have read+write (for hardlinks to work)
    if !file.GroupWritable() {
        issues = append(issues, models.PermissionIssue{
            Path: file.Path,
            Issue: "not_group_writable",
            Severity: "warning",
            FixHint: fmt.Sprintf("Group cannot write to file. Run: sudo chmod g+w '%s'", file.Path),
        })
    }
    
    // Check 4: Directories in media paths should have SGID bit
    if file.IsDirectory && pa.shouldHaveSGID(file.Path) && !file.HasSGID() {
        issues = append(issues, models.PermissionIssue{
            Path: file.Path,
            Issue: "missing_sgid",
            Severity: "warning",
            FixHint: fmt.Sprintf("Directory missing SGID bit (new files won't inherit arr_stack group). Run: sudo chmod g+s '%s'", file.Path),
        })
    }
    
    // Check 5: Warn if permissions are too restrictive (not 664/775)
    if file.IsDirectory {
        if file.Mode&0777 != 0775 {
            issues = append(issues, models.PermissionIssue{
                Path: file.Path,
                Issue: "nonstandard_permissions",
                Severity: "info",
                FixHint: fmt.Sprintf("Directory mode is %s, expected 2775 or 0775. Current: %s", 
                    file.ModeString(), file.ModeString()),
            })
        }
    } else {
        // Files should be 664 (rw-rw-r--)
        if file.Mode&0666 != 0664 {
            issues = append(issues, models.PermissionIssue{
                Path: file.Path,
                Issue: "nonstandard_permissions",
                Severity: "info",
                FixHint: fmt.Sprintf("File mode is %s, expected 664. Run: sudo chmod 664 '%s'", 
                    file.ModeString(), file.Path),
            })
        }
    }
    
    return issues
}
```

**Configuration:**

```toml
[permissions]
# Enable permission auditing (default: true)
enabled = true

# Expected group (arr_stack) - must match your NixOS setup
group_gid = 1000

# Allowed UIDs that can own files (sonarr, radarr, qbittorrent, etc.)
# These come from your nixos_flakes users.nix configuration
allowed_uids = [1001, 1002, 1004, 1005, 1006, 1007, 1008]

# Paths that should have SGID bit set (directories where new files should inherit group)
# These match your storage.nix tmpfiles rules
sgid_paths = [
    "/mnt/media-arr/media",
    "/mnt/media-arr/media/tv", 
    "/mnt/media-arr/media/movies",
    "/mnt/media-arr/media/music",
]

# Paths to skip (optional)
skip_paths = [
    "/mnt/media-arr/torrents",  # Different permission model acceptable
]

# Severity for nonstandard permissions (info, warning, error)
nonstandard_severity = "warning"
```

**Permission Issues to Report:**

| Issue | Severity | Description | Example Fix |
|-------|----------|-------------|-------------|
| wrong_owner | error | File owned by unexpected user | `chown sonarr:arr_stack file` |
| wrong_group | error | File not in arr_stack group | `chgrp arr_stack file` |
| not_group_writable | warning | Group can't write (blocks hardlinks) | `chmod g+w file` |
| missing_sgid | warning | Directory lacks SGID bit | `chmod g+s directory` |
| too_permissive | warning | World writable (777) | `chmod o-w file` |
| nonstandard | info | Not 664/775 but functional | Document only |

**Report Section:**

```markdown
## Permission Issues

### Critical (Prevents Hardlinks)

| Path | Issue | Current | Fix Command |
|------|-------|---------|-------------|
| `/mnt/media-arr/media/tv/Show/S01E01.mkv` | wrong_group | root:users (100:100) | `sudo chgrp arr_stack '/mnt/media-arr/media/tv/Show/S01E01.mkv'` |
| `/mnt/media-arr/media/movies/Movie/movie.mkv` | wrong_owner | UID 0 (root) | `sudo chown radarr:arr_stack '/mnt/media-arr/media/movies/Movie/movie.mkv'` |

### Warnings (Best Practice Violations)

| Path | Issue | Current | Recommendation |
|------|-------|---------|----------------|
| `/mnt/media-arr/media/tv` | missing_sgid | 0755 | `sudo chmod g+s '/mnt/media-arr/media/tv'` |
| `/mnt/media-arr/torrents/release.mkv` | not_group_writable | 0644 | `sudo chmod g+w '/mnt/media-arr/torrents/release.mkv'` |

### Permission Audit Summary
- Files checked: 1,234
- Critical issues: 2 (affect hardlink functionality)
- Warnings: 5 (best practice violations)
- All clear: 1,227 files
```

**Integration with AnalysisResult:**

```go
type AnalysisResult struct {
    ClassifiedMedia    []models.ClassifiedMedia
    SuspiciousFiles    []models.SuspiciousFile
    UnlinkedTorrents   []models.Torrent
    PermissionIssues   []models.PermissionIssue  // NEW
    Summary            SummaryStats
}
```

**Checkpoints:**
- [ ] Define FilePermissions and PermissionIssue models
- [ ] Implement permission extraction during filesystem walk (syscall.Stat_t)
- [ ] Implement permission validation logic
- [ ] Add permission section to markdown report
- [ ] Add permission configuration to TOML config
- [ ] Test against real arr_stack setup on louise
- [ ] Verify fix commands are accurate and safe

---

## Phase 4: Reporting

### Step 4.1: Markdown Report Generator

**Report Structure:**

```markdown
# Media Audit Report

**Generated**: 2024-01-15 14:32:15  
**Duration**: 45.2 seconds

## Summary

| Category | Count | Status | Description |
|----------|-------|--------|-------------|
| Healthy Media | 1,234 | ✅ | Tracked by Arr and hardlinked to torrent |
| At Risk | 3 | ⚠️ | Tracked by Arr but NOT hardlinked (no torrent protection) |
| Orphaned | 5 | ❌ | Not tracked by Arr (outside grace window) |
| Suspicious Files | 1 | 🚨 | Suspicious extensions detected |
| Permission Issues | 2 | ⚠️ | Files with incorrect permissions (affecting hardlinks) |

## Permission Issues

### Critical (Prevents Hardlinks)

| Path | Issue | Current | Fix Command |
|------|-------|---------|-------------|
| `/mnt/media-arr/media/tv/Show/S01E01.mkv` | wrong_group | root:users | `sudo chgrp arr_stack '...'` |

### Warnings (Best Practice Violations)

| Path | Issue | Current | Recommendation |
|------|-------|---------|----------------|
| `/mnt/media-arr/media/tv` | missing_sgid | 0755 | `sudo chmod g+s '/mnt/media-arr/media/tv'` |

## At Risk Media

These files are tracked by Sonarr/Radarr but have no hardlink protection:

| Path | Source | Age |
|------|--------|-----|
| `/mnt/media-arr/media/tv/Show Name/S01E01.mkv` | Sonarr | 72 hours |
| `/mnt/media-arr/media/movies/Movie Name/movie.mkv` | Radarr | 96 hours |

## Orphaned Media

Files not tracked by any Arr service:

| Path | Age |
|------|-----|
| `/mnt/media-arr/media/tv/Old Show/episode.mkv` | 45 days |

## Suspicious Files

| Path | Reason |
|------|--------|
| `/mnt/media-arr/media/movies/Bad Movie/setup.exe` | suspicious_extension |

## Unlinked Torrents

Completed torrents with no matching media:

| Torrent Name | Save Path | Completed |
|--------------|-----------|-----------|
| `Some.Release.1080p` | `/mnt/media-arr/torrents/tv/` | 3 days ago |

## Configuration

- Sonarr Grace: 48 hours
- Radarr Grace: 48 hours
- qBittorrent Grace: 24 hours
```

**Implementation:**

```go
// internal/reporting/markdown.go
package reporting

type MarkdownFormatter struct{}

func (mf *MarkdownFormatter) Format(result *analysis.AnalysisResult) (string, error) {
    var buf bytes.Buffer
    
    // Write header with timestamp
    // Write summary table
    // Group files by classification
    // Include configuration summary
    
    return buf.String(), nil
}
```

**Checkpoints:**
- [ ] Implement report header generation
- [ ] Create summary statistics section
- [ ] Implement grouped file tables
- [ ] Add configuration metadata
- [ ] Ensure proper markdown table formatting
- [ ] Write to timestamped file in report_dir

### Step 4.2: Discord Notification

**Notification Format:**

```
Media Audit Complete
━━━━━━━━━━━━━━━━━━

📊 Summary:
• 1,234 healthy files (tracked + hardlinked)
• ⚠️ 3 at risk (tracked, NOT hardlinked)
• ❌ 5 orphaned (not tracked by Arr)
• 🚨 1 suspicious file
• ⚠️ 2 permission issues (affecting hardlinks)

📁 Report: /var/lib/auditarr/reports/2024-01-15-report.md

Note: Files within grace window are excluded to avoid false positives during imports.

Run details:
Duration: 45.2s
Media scanned: 1,500 files
Torrents checked: 200
```

**Implementation:**

```go
// internal/reporting/notification.go
package reporting

type DiscordNotifier struct {
    webhookURL string
    client     *http.Client
}

func (dn *DiscordNotifier) Send(result *analysis.AnalysisResult, reportPath string) error {
    // Build Discord webhook payload
    // Include summary only, not full report
    // Add report file path for reference
    // Send HTTP POST to webhook URL
}
```

**Discord Webhook Payload:**

```json
{
  "content": null,
  "embeds": [{
    "title": "Media Audit Complete",
    "color": 3447003,
    "fields": [
      {
        "name": "Summary",
        "value": "✅ 1,234 healthy (tracked + hardlinked)\n⚠️ 3 at risk (tracked, NOT hardlinked)\n❌ 5 orphaned (not tracked)\n🚨 1 suspicious file"
      },
      {
        "name": "Report Location",
        "value": "/var/lib/auditarr/reports/2024-01-15-report.md"
      }
    ],
    "footer": {
      "text": "Duration: 45.2s"
    }
  }]
}
```

**Checkpoints:**
- [ ] Implement Discord webhook client
- [ ] Build summary payload
- [ ] Handle webhook delivery errors gracefully
- [ ] Add webhook URL validation
- [ ] Test against real Discord webhook

---

## Phase 5: CLI and Main Entry Point

### Step 5.1: CLI Structure

**Commands:**

```bash
# One-time scan (works standalone, outside systemd)
auditarr scan --config=/etc/auditarr/config.toml

# Run with nix flake directly
nix run github:jdpx/auditarr -- scan --config=/etc/auditarr/config.toml

# Future: Serve reports via HTTP
auditarr serve --config=/etc/auditarr/config.toml --port=8080

# Help
auditarr --help
auditarr scan --help
```

**Standalone vs NixOS Service:**

The binary works in two modes:

1. **Standalone CLI**: Run directly as user `auditarr scan --config=...`
   - Good for testing, development
   - Can use any config file
   - Runs as current user

2. **Via NixOS Systemd**: `systemctl start auditarr` (or automatic timer)
   - Uses dedicated service user (`auditarr`)
   - Reads from production config at `/etc/auditarr/config.toml`
   - Writes reports to `/var/lib/auditarr/reports/`

**Implementation:**

```go
// cmd/auditarr/main.go
package main

import (
    "flag"
    "fmt"
    "os"
    "time"
    
    "github.com/jdpx/auditarr/internal/config"
    "github.com/jdpx/auditarr/internal/collectors"
    "github.com/jdpx/auditarr/internal/analysis"
    "github.com/jdpx/auditarr/internal/reporting"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintln(os.Stderr, "Usage: auditarr <command> [options]")
        fmt.Fprintln(os.Stderr, "Commands:")
        fmt.Fprintln(os.Stderr, "  scan    Run one-time audit")
        os.Exit(1)
    }
    
    switch os.Args[1] {
    case "scan":
        runScan(os.Args[2:])
    default:
        fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
        os.Exit(1)
    }
}

func runScan(args []string) {
    fs := flag.NewFlagSet("scan", flag.ExitOnError)
    configPath := fs.String("config", "/etc/auditarr/config.toml", "Path to configuration file")
    fs.Parse(args)
    
    // Load configuration
    cfg, err := config.Load(*configPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
        os.Exit(1)
    }
    
    // Execute scan workflow
    startTime := time.Now()
    
    // 1. Collect filesystem data
    // 2. Collect Arr data
    // 3. Collect torrent data
    // 4. Analyze
    // 5. Generate report
    // 6. Send notification
    
    duration := time.Since(startTime)
    fmt.Printf("Audit complete in %.2f seconds\n", duration.Seconds())
}
```

**Checkpoints:**
- [ ] Implement command-line parsing
- [ ] Add --config flag with default
- [ ] Implement scan workflow orchestration
- [ ] Add progress logging to stdout
- [ ] Proper exit codes (0 for success, non-zero for errors)

### Step 5.2: Error Handling and Logging

**Strategy:**
- Log progress to stdout (collection phases, counts)
- Log errors to stderr
- Continue on non-fatal errors (e.g., one API failure shouldn't stop entire scan)
- Fatal errors: config loading, filesystem permission errors

**Implementation Pattern:**

```go
// Non-fatal: log and continue
files, err := collector.Collect(ctx)
if err != nil {
    log.Printf("Warning: Failed to collect from %s: %v", collector.Name(), err)
    // Continue with partial data
}

// Fatal: exit
config, err := config.Load(path)
if err != nil {
    log.Fatalf("Failed to load configuration: %v", err)
}
```

**Checkpoints:**
- [ ] Implement structured logging
- [ ] Define fatal vs non-fatal error taxonomy
- [ ] Add verbose mode flag (--verbose)
- [ ] Ensure all errors are actionable

---

## Phase 6: Testing

### Step 6.1: Unit Tests

**Coverage Areas:**
- Configuration loading and validation
- Model helper methods (grace windows, state checks)
- Classification rules (all paths)
- Suspicious file detection
- Path normalization utilities

**Checkpoints:**
- [ ] Unit tests for config package
- [ ] Unit tests for models package
- [ ] Unit tests for analysis rules
- [ ] Unit tests for suspicious detection
- [ ] Target: >80% coverage on core logic

### Step 6.2: Integration Tests

**Test Environment:**
- Docker Compose with Sonarr, Radarr, qBittorrent
- Mock filesystem with test data
- Real API interactions

**Test Scenarios:**
- Healthy library (all hardlinked)
- Active import scenario (files within grace)
- Orphaned files present
- Suspicious files present
- API connection failures

**Checkpoints:**
- [ ] Docker Compose test environment
- [ ] Integration test for full scan workflow
- [ ] Test data generators
- [ ] CI/CD pipeline integration

### Step 6.3: Manual Testing Plan

**Test Cases:**
1. **Happy Path**: Run against production louise, verify report looks correct
2. **Grace Window Test**: Create new file, run audit, verify it's ignored
3. **Orphan Detection**: Move file out of Arr management, verify flagged
4. **API Failure**: Stop Sonarr, run audit, verify graceful handling
5. **Large Library**: Test with 10k+ files, verify performance acceptable

**Checkpoints:**
- [ ] Test on louise staging environment
- [ ] Performance benchmark (target: <5 min for typical library)
- [ ] Validate Discord notifications
- [ ] Confirm no false positives during normal operations

---

## Phase 7: Documentation

### Step 7.1: User Documentation

**README.md Contents:**
1. Quick start guide
2. Configuration reference
3. Understanding reports
4. FAQ (common false positives, troubleshooting)

**Checkpoints:**
- [ ] Installation instructions
- [ ] Configuration examples
- [ ] Report interpretation guide
- [ ] Troubleshooting section

### Step 7.2: Developer Documentation

**Contents:**
1. Architecture overview
2. Adding new collectors (extensibility guide)
3. Testing guide

**Checkpoints:**
- [ ] Architecture diagrams
- [ ] API integration notes
- [ ] Contributing guidelines

---

## Phase 8: Deployment on Louise (NixOS)

### Nix Flakes - Quick Answers

**Q: Can we use Nix flakes for this project?**
A: **Yes.** The implementation is designed as a Nix flake with:
- `flake.nix` defining the package and dev shell
- `nix run . -- scan --config=...` for immediate execution
- `nixosModules.default` for system-level integration

**Q: How do we configure the frequency?**
A: **Three ways:**
1. **Automatic**: Set `services.auditarr.schedule` in configuration.nix using systemd calendar expressions:
   - `"monthly"` (default) - 1st of month at midnight
   - `"weekly"` - Every Monday at midnight
   - `"*-*-01,15 03:00:00"` - 1st and 15th at 3am
   - Any valid systemd.time(7) expression
2. **Manual only**: Set `schedule = null` and trigger via `systemctl start auditarr`
3. **Ad-hoc**: Run `nix run . -- scan --config=...` directly from the repo

**Q: Can we trigger it outside of the cron schedule?**
A: **Yes, multiple ways:**
- `sudo systemctl start auditarr` - Triggers the systemd service immediately
- `nix run github:jdpx/auditarr -- scan --config=/etc/auditarr/config.toml` - Run directly
- `auditarr scan --config=/etc/auditarr/config.toml` - If binary is in PATH

The systemd service is defined as `Type = "oneshot"`, meaning it can be triggered on-demand without affecting the timer schedule.

---

### Step 8.1: Nix Flake Package

**flake.nix:**

```nix
{
  description = "Media audit tool for Arr-managed libraries";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = rec {
          auditarr = pkgs.buildGoModule rec {
            pname = "auditarr";
            version = "0.1.0";
            
            src = ./.;  # Local source
            
            vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";  # Update with: nix run .#update-vendor
            
            meta = with pkgs.lib; {
              description = "Non-destructive audit tool for Arr media libraries";
              license = licenses.mit;
            };
          };
          default = auditarr;
        };
        
        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.auditarr;
        };
        
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ go golangci-lint ];
        };
      });
}
```

**Build & Run:**

```bash
# Build the package
nix build

# Run directly
nix run . -- scan --config=/etc/auditarr/config.toml

# Update vendor hash after go.mod changes
nix run .#update-vendor  # Custom script to update hash
```

**Checkpoints:**
- [ ] Create flake.nix with buildGoModule
- [ ] Add vendorHash (update after go.mod changes)
- [ ] Test build: `nix build`
- [ ] Test run: `nix run . -- --help`

### Step 8.2: NixOS Module

**module.nix:**

```nix
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.auditarr;
in
{
  options.services.auditarr = {
    enable = mkEnableOption "media audit service";
    
    configFile = mkOption {
      type = types.path;
      description = "Path to auditarr configuration file";
    };
    
    package = mkOption {
      type = types.package;
      default = pkgs.auditarr;
      description = "auditarr package to use";
    };
    
    schedule = mkOption {
      type = types.str;
      default = "monthly";
      description = ''
        Systemd calendar expression for schedule.
        Examples:
        - "monthly" - First day of each month at midnight
        - "weekly" - Monday at midnight
        - "daily" - Every day at midnight
        - "*-*-01,15 02:00:00" - 1st and 15th at 2am
        - "Sun *-*-* 03:00:00" - Every Sunday at 3am
        See: man 7 systemd.time for full syntax
      '';
    };
    
    user = mkOption {
      type = types.str;
      default = "auditarr";
    };
    
    group = mkOption {
      type = types.str;
      default = "auditarr";
    };
  };
  
  config = mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/auditarr";
      createHome = true;
    };
    
    users.groups.${cfg.group} = {};
    
    # The service can be triggered manually via: systemctl start auditarr
    systemd.services.auditarr = {
      description = "Media Library Audit";
      serviceConfig = {
        Type = "oneshot";
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/auditarr scan --config=${cfg.configFile}";
        StateDirectory = "auditarr";  # Creates /var/lib/auditarr owned by service user
        # Note: report_dir in config.toml should match StateDirectory path
        # or use WorkingDirectory to set a different base path
      };
    };
    
    # Timer triggers the service on schedule
    # Can be disabled by setting schedule to null (if you only want manual runs)
    systemd.timers.auditarr = mkIf (cfg.schedule != null) {
      description = "Run media audit on schedule";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.schedule;
        Persistent = true;  # Run missed executions on boot if system was down
      };
    };
  };
}
```

**Frequency Configuration:**

The `schedule` option uses systemd calendar expressions. Common patterns:

```nix
# louise configuration.nix
services.auditarr = {
  enable = true;
  configFile = "/etc/auditarr/config.toml";
  
  # Options:
  # schedule = "monthly";                    # First of month at midnight (default)
  # schedule = "weekly";                     # Every Monday at midnight
  # schedule = "daily";                      # Every day at midnight
  # schedule = "*-*-01 03:00:00";            # 1st of month at 3am
  # schedule = "Sun *-*-* 04:00:00";         # Every Sunday at 4am
  # schedule = "*-*-01,15 02:00:00";         # 1st and 15th at 2am
  schedule = "monthly";  # Default
};
```

**Manual Execution:**

Even with automatic scheduling, you can trigger runs manually:

```bash
# Start the service immediately (respects config file)
sudo systemctl start auditarr

# View service status
sudo systemctl status auditarr

# View recent logs
sudo journalctl -u auditarr -n 50

# Run with different config (one-off, bypasses systemd)
sudo -u auditarr /run/current-system/sw/bin/auditarr scan --config=/tmp/test-config.toml
```

**Disabling Automatic Schedule (Manual Only):**

```nix
services.auditarr = {
  enable = true;
  configFile = "/etc/auditarr/config.toml";
  schedule = null;  # No automatic timer, only manual runs via systemctl start
};
```

**Checkpoints:**
- [ ] Create NixOS module
- [ ] Define all configuration options
- [ ] Implement systemd service (triggerable manually)
- [ ] Implement systemd timer with schedule option
- [ ] Create user and group
- [ ] Set up StateDirectory for reports
- [ ] Test manual execution: `systemctl start auditarr`
- [ ] Test automatic execution via timer

### Step 8.3: Louise Integration

**In louise's flake.nix:**

```nix
{
  description = "Louise NixOS configuration";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    auditarr = {
      url = "github:jdpx/auditarr";  # Or path:/path/to/local/repo for development
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, auditarr, ... }:
    {
      nixosConfigurations.louise = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          ./configuration.nix
          auditarr.nixosModules.default  # Import the NixOS module
        ];
      };
    };
}
```

**In louise's configuration.nix:**

```nix
{ config, pkgs, ... }:

{
  # Import the service module and configure it
  services.auditarr = {
    enable = true;
    
    # Use the package from the flake input
    package = inputs.auditarr.packages.${pkgs.system}.auditarr;
    
    configFile = "/etc/auditarr/config.toml";
    
    # Schedule options:
    # schedule = "monthly";                    # Default: first of month at midnight
    # schedule = "weekly";                     # Every Monday at midnight
    # schedule = "*-*-01,15 03:00:00";         # 1st and 15th at 3am
    schedule = "monthly";
  };
  
  # Create the config file
  environment.etc."auditarr/config.toml".text = ''
    [paths]
    media_root = "/mnt/media-arr/media"
    torrent_root = "/mnt/media-arr/torrents"
    
    [sonarr]
    url = "http://localhost:8989"
    api_key = "your-api-key"
    grace_hours = 48
    
    [radarr]
    url = "http://localhost:7878"
    api_key = "your-api-key"
    grace_hours = 48
    
    [qbittorrent]
    url = "http://localhost:8080"
    username = "admin"
    password = "your-password"
    grace_hours = 24
    
    [notifications]
    discord_webhook = "https://discord.com/api/webhooks/..."
    
    [outputs]
    report_dir = "/var/lib/auditarr/reports"
  '';
}
```

**Operations on Louise:**

```bash
# Check when next run is scheduled
systemctl list-timers auditarr

# Trigger manual run immediately
sudo systemctl start auditarr

# View timer status
sudo systemctl status auditarr.timer

# View recent logs
sudo journalctl -u auditarr -n 100 -f

# List generated reports
ls -la /var/lib/auditarr/reports/

# View latest report
cat /var/lib/auditarr/reports/$(ls -t /var/lib/auditarr/reports/ | head -1)
```

**Checkpoints:**
- [ ] Add auditarr flake input to louise's flake.nix
- [ ] Import auditarr.nixosModules.default in system configuration
- [ ] Configure services.auditarr with appropriate schedule
- [ ] Create /etc/auditarr/config.toml with correct paths and API keys
- [ ] Ensure auditarr user can read /mnt/media-arr/ paths
- [ ] Ensure auditarr user can reach Sonarr/Radarr/qBittorrent APIs
- [ ] Test manual execution: `systemctl start auditarr`
- [ ] Verify Discord notifications arrive
- [ ] Verify reports are written to /var/lib/auditarr/reports/

---

## Phase 9: Future Enhancements (Post-MVP)

These are intentionally NOT part of v1 but designed to be possible extensions:

### Possible Future Features

1. **Interactive Web UI**
   - `auditarr serve` subcommand
   - Browse reports historically
   - Drill down into classifications
   - Mark files as "known good" (persistent ignore list)

2. **Trend Analysis**
   - SQLite database for historical tracking
   - "Orphaned files increased by 50% this month"
   - Graphs over time

3. **Additional Collectors**
   - Deluge/Transmission support
   - Lidarr/Readarr/Bazarr support
   - Custom script collectors

4. **Notification Channels**
   - Email (SMTP)
   - Slack
   - Pushover/Pushbullet

5. **Advanced Scheduling**
   - Built-in cron-like scheduler
   - Trigger on events (Arr webhook)
   - Ad-hoc API endpoints

6. **Report Enhancements**
   - HTML reports with search/filter
   - CSV export for spreadsheet analysis
   - JSON export for programmatic use

7. **Safety Features**
   - Dry-run mode (no notifications)
   - Configurable thresholds (don't notify unless >10 orphans)
   - Rate limiting for notifications

---

## Development Workflow

### Git Repository Structure

```
auditarr/
├── cmd/auditarr/
│   └── main.go
├── internal/
│   ├── analysis/
│   ├── collectors/
│   ├── config/
│   ├── models/
│   ├── reporting/
│   └── utils/
├── test/
│   ├── integration/
│   └── fixtures/
├── docs/
│   ├── README.md
│   └── CONFIGURATION.md
├── nix/
│   ├── default.nix
│   └── module.nix
├── go.mod
├── go.sum
├── Makefile
└── .github/
    └── workflows/
        └── ci.yml
```

### CI/CD Pipeline

**GitHub Actions:**
1. **Test**: Run unit tests on every PR
2. **Lint**: golangci-lint, go vet
3. **Build**: Build binary for Linux amd64
4. **Integration**: Run integration tests with Docker Compose
5. **Release**: Build and publish release artifacts on tag

### Versioning Strategy

- Follow semantic versioning
- v0.1.0: MVP with core features
- v0.2.0: Bug fixes and polish
- v1.0.0: Production ready with full test coverage

---

## Success Criteria

**MVP is complete when:**

- [ ] Binary successfully builds and runs on louise
- [ ] Configuration file is validated and loaded
- [ ] All collectors (filesystem, Sonarr, Radarr, qBittorrent) execute
- [ ] Classification rules correctly identify healthy, at-risk, and orphaned files (pending import not used in v1)
- [ ] Suspicious file detection flags bad extensions
- [ ] Permission auditing validates arr_stack setup (group, SGID, writable)
- [ ] Markdown report is generated with proper grouping
- [ ] Discord notification is sent with summary
- [ ] Report file is written to configured directory
- [ ] No false positives during normal operations
- [ ] Grace windows correctly filter out recent files/torrents
- [ ] Unmonitored items are treated as "known" and classified normally (healthy if hardlinked, at-risk if not)
- [ ] All filesystem operations are read-only
- [ ] Error handling is graceful (continues on non-fatal errors)

**Quality Criteria:**

- [ ] Unit test coverage >80% for core logic
- [ ] Integration tests pass
- [ ] Manual testing on louise confirms accuracy
- [ ] Documentation is complete and clear
- [ ] NixOS module is functional
- [ ] No panics or crashes during execution

---

## Checkpoint Summary for AI Assistants

When working through this plan, use these checkpoints to track progress:

**Phase 1: Foundation**
- [ ] 1.1 Project structure created
- [ ] 1.2 Configuration layer implemented
- [ ] 1.3 Core models defined

**Phase 2: Data Collection**
- [ ] 2.1 Filesystem collector implemented
- [ ] 2.2 Sonarr collector implemented
- [ ] 2.3 Radarr collector implemented
- [ ] 2.4 qBittorrent collector implemented

**Phase 3: Analysis**
- [ ] 3.1 Signal combination logic
- [ ] 3.2 Classification rules
- [ ] 3.3 Suspicious file detection
- [ ] 3.4 Permission auditing (arr_stack group validation)

**Phase 4: Reporting**
- [ ] 4.1 Markdown report generator
- [ ] 4.2 Discord notifier

**Phase 5: CLI**
- [ ] 5.1 CLI structure and commands
- [ ] 5.2 Error handling and logging

**Phase 6: Testing**
- [ ] 6.1 Unit tests
- [ ] 6.2 Integration tests
- [ ] 6.3 Manual testing

**Phase 7: Documentation**
- [ ] 7.1 User documentation
- [ ] 7.2 Developer documentation

**Phase 8: Deployment**
- [ ] 8.1 Nix derivation
- [ ] 8.2 NixOS module
- [ ] 8.3 Louise integration

---

## Notes for Implementation

### Key Technical Decisions to Remember

1. **Statelessness**: No database between runs. Each scan is independent.
2. **Grace Windows**: Files/torrents within grace window are ignored entirely (not flagged as pending).
3. **Unmonitored**: Valid state. Unmonitored Arr items are treated as "known" and healthy if hardlinked.
4. **Hardlinks**: Use syscall.Stat_t.Nlink on Linux. Count > 1 means hardlinked.
5. **Read-Only**: Never delete, move, or modify files. Never modify Arr or torrent state.
6. **Error Handling**: Fatal: config errors, permission denied. Non-fatal: API failures (log and continue).
7. **Notifications**: High-level summary only. Full details in report file.
8. **Extensibility**: Interface-based collectors for future additions.
9. **Permissions**: Audit only - provide fix commands but never auto-fix. All checks against arr_stack GID 1000.

### Common Pitfalls to Avoid

1. **Following symlinks**: Decide whether to follow or skip symlinks in filesystem walk. Skip is safer.
2. **Path normalization**: Ensure consistent path comparison (absolute vs relative, trailing slashes).
3. **Timezone handling**: Use UTC consistently for all timestamps.
4. **API rate limiting**: Add basic rate limiting for API clients to avoid hammering Arr services.
5. **Large directories**: Use WalkDir instead of Walk for better performance.
6. **Hardlink detection on macOS**: syscall.Stat_t works differently on macOS vs Linux. Document limitation.

### Performance Targets

- Scan 10,000 files in < 2 minutes
- Memory usage < 500MB for typical library
- API calls batched where possible
- Concurrent collectors (with rate limiting)
