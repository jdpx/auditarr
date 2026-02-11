# Agent.md - Media Audit Service (auditarr)

## Project Overview

**Repository**: `github.com/jdpx/auditarr`  
**Binary Name**: `auditarr`  
**Language**: Go  
**Deployment**: NixOS (louise server)

A non-destructive, stateless audit tool for Arr-managed media libraries (Sonarr, Radarr, qBittorrent). Provides visibility into media health without any automated remediation.

## Core Principles (MUST FOLLOW)

1. **Non-destructive**: Read-only operations only. NO file modifications, NO deletions.
2. **Stateless**: No database, no historical state between runs. Each run is independent.
3. **Simple**: Single Go binary, minimal dependencies.
4. **Extensible**: Design for future enhancements without adding complexity now.

## Architecture

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
│   ├── classification.go    # Classification enum/types
│   └── permissions.go       # Permission auditing models
├── analysis/
│   ├── engine.go            # Signal combination logic
│   ├── rules.go             # Classification rule implementations
│   └── suspicious.go        # Suspicious file detection
├── reporting/
│   ├── generator.go         # Report generation coordinator
│   ├── markdown.go          # Markdown output formatter
│   └── notification.go      # Discord webhook sender
└── utils/
    ├── paths.go             # Path utilities
    └── validators.go        # Input validation
```

## Key Rules

### 1. Configuration
- TOML format only
- Secrets stored in plaintext (operational decision) - config file must be chmod 600
- Platform-specific defaults for report_dir:
  - Linux/NixOS: /var/lib/auditarr/reports
  - macOS: ~/Library/Application Support/auditarr/reports
  - Other: ./reports

### 2. Media Classification (3 states only)
- **Healthy**: Tracked by Arr AND hardlinked to torrent
- **At Risk**: Tracked by Arr but NOT hardlinked (no torrent protection)
- **Orphan**: Not tracked by Arr (outside grace window)

**Important**: MediaPendingImport is NOT used in v1. Files within grace window are excluded entirely.

### 3. Grace Windows
- Sonarr/Radarr: 48 hours (configurable)
- qBittorrent: 24 hours (configurable)
- Files within grace window are excluded from reports entirely to avoid false positives during imports
- Zero or negative graceHours means no grace window (all files considered outside grace)

### 4. Classification Logic
1. Check grace window first - if within, skip entirely (don't classify, don't report)
2. If outside grace and unknown to Arr → Orphan
3. If outside grace, known to Arr, and hardlinked → Healthy
4. If outside grace, known to Arr, and not hardlinked → At Risk

### 5. Filesystem Collection
- Walk media_root only
- Do NOT walk torrent_root - torrent info comes from qBittorrent API
- Use filepath.WalkDir for efficiency
- Extract hardlink count via syscall.Stat_t.Nlink
- Handle symlinks appropriately
- Skip hidden files/directories

### 6. Permission Auditing
Purpose: Validate file/directory permissions match Trash Guides best practices and NixOS arr_stack setup.

**Expected Setup**:
- Group: arr_stack (GID 1000)
- Users: sonarr(1001), radarr(1002), qbittorrent(1004), etc.
- Directories: 2775 (SGID bit set)
- Files: 664 (rw-rw-r--)

**Permission Issues to Report**:
- wrong_owner (error): File owned by unexpected user
- wrong_group (error): File not in arr_stack group
- not_group_writable (warning): Group can't write (blocks hardlinks)
- missing_sgid (warning): Directory lacks SGID bit
- nonstandard_permissions (info/warning): Not 664/775 but functional

### 7. Error Handling
- Log progress to stdout
- Log errors to stderr
- Continue on non-fatal errors (one API failure shouldn't stop entire scan)
- Fatal errors: config loading, filesystem permission errors
- Non-fatal: individual collector failures, API timeouts

### 8. Reporting
- Markdown format reports written to report_dir with timestamps
- Discord notifications with summary only (not full report)
- Include configuration summary in reports
- Group files by classification in tables

## CLI Commands

```bash
# One-time scan (standalone)
auditarr scan --config=/etc/auditarr/config.toml

# Run via nix flake
nix run github:jdpx/auditarr -- scan --config=/etc/auditarr/config.toml

# Manual trigger on NixOS
sudo systemctl start auditarr
```

## Dependencies

Minimal external dependencies:
- `github.com/BurntSushi/toml` (TOML parsing only)
- Standard library for everything else (no external HTTP clients)

## Testing Requirements

- Unit test coverage >80% for core logic
- Integration tests with Docker Compose (Sonarr, Radarr, qBittorrent)
- Manual testing on louise (NixOS server)
- Performance target: <5 min for typical library

## Success Criteria

**MVP Complete When**:
- [ ] Binary builds and runs on louise
- [ ] Configuration validated and loaded
- [ ] All collectors execute successfully
- [ ] Classification rules work correctly (healthy, at-risk, orphan)
- [ ] Suspicious file detection functional
- [ ] Permission auditing validates arr_stack setup
- [ ] Markdown report generated
- [ ] Discord notification sent
- [ ] No false positives during normal operations
- [ ] Grace windows filter recent files correctly
- [ ] All filesystem operations are read-only
- [ ] Graceful error handling (continues on non-fatal)

## Implementation Phases

1. **Phase 1: Foundation** - Project structure, config, core models
2. **Phase 2: Data Collection** - Filesystem, Sonarr, Radarr, qBittorrent collectors
3. **Phase 3: Analysis** - Signal combination, classification rules, suspicious detection, permission auditing
4. **Phase 4: Reporting** - Markdown generator, Discord notifier
5. **Phase 5: CLI** - Command structure, error handling
6. **Phase 6: Testing** - Unit, integration, manual tests
7. **Phase 7: Documentation** - User and developer docs
8. **Phase 8: NixOS Deployment** - Flake, module, louise integration

## Code Style

- Follow existing code patterns
- Use standard Go naming conventions
- Add unit tests for all core logic
- NO comments unless explaining non-obvious behavior
- Error messages must be actionable

## Security Notes

- Config file contains plaintext secrets (API keys, passwords)
- Config must be readable only by root/auditarr user (chmod 600)
- All filesystem operations are read-only
- No exposure of sensitive data in logs or reports

## Future Enhancements (NOT for v1)

- Web UI for browsing reports
- Historical trend analysis (requires database)
- Additional collectors (Deluge, Transmission, Lidarr, etc.)
- Additional notification channels (Email, Slack)
- HTML/CSV/JSON report formats
- Dry-run mode

## Common Tasks

### Adding a new collector
1. Create file in `internal/collectors/`
2. Implement `Collector` interface
3. Add to config if needed
4. Add unit tests
5. Add integration test

### Adding a classification rule
1. Update `internal/models/classification.go` if new type needed
2. Implement logic in `internal/analysis/rules.go`
3. Update `ClassifyMedia()` function
4. Add unit tests for all paths
5. Update report formatter

### Adding a new report section
1. Update `AnalysisResult` struct
2. Add generation logic in `internal/reporting/markdown.go`
3. Update Discord formatter if summary needed
4. Update summary statistics

## Troubleshooting

**Permission Denied Errors**: Ensure auditarr user has read access to media paths and API endpoints.

**False Positives**: Check grace window settings. Files recently imported may still be within grace period.

**Missing Hardlinks**: Verify SGID bit is set on directories (chmod g+s). Check group ownership matches arr_stack.

**API Connection Failures**: Verify URLs and credentials in config. Ensure services are running and accessible.
