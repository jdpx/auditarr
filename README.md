# Auditarr

A non-destructive, stateless audit tool for Arr-managed media libraries. Provides visibility into media health without any automated remediation.

## Features

- **Non-destructive**: Read-only operations on filesystem and APIs
- **Stateless**: No database, no historical state between runs
- **Simple**: Single Go binary, minimal dependencies
- **Smart Classification**:
  - **Healthy**: Tracked by Arr and hardlinked to torrent
  - **At Risk**: Tracked by Arr but NOT hardlinked (no torrent protection)
  - **Orphan**: Not tracked by any Arr service
- **Grace Windows**: Files within 48h (Arr) / 24h (torrents) are excluded to avoid false positives during imports
- **Permission Auditing**: Validates arr_stack setup (correct group, SGID bits, writable permissions)
- **Suspicious File Detection**: Flags suspicious extensions

## Quick Start

### Build Locally

```bash
# Build
nix build

# Or with Go
go build -o auditarr ./cmd/auditarr

# Run
./auditarr scan --config=/etc/auditarr/config.toml
```

### Configuration

See `config.example.toml` for a complete configuration example.

```toml
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

[permissions]
enabled = true
group_gid = 1000
allowed_uids = [1001, 1002, 1003, 1004, 1005]
sgid_paths = ["/mnt/media-arr/media"]
```

## NixOS Deployment

### Add to Louise's Flake

```nix
{
  inputs.auditarr.url = "github:jdpx/auditarr";
  
  outputs = { self, nixpkgs, auditarr, ... }: {
    nixosConfigurations.louise = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        auditarr.nixosModules.default
      ];
    };
  };
}
```

### Configure Service

```nix
# In configuration.nix
services.auditarr = {
  enable = true;
  configFile = "/etc/auditarr/config.toml";
  
  # Schedule options:
  # schedule = "monthly";              # First of month at midnight (default)
  # schedule = "weekly";               # Every Monday at midnight
  # schedule = "daily";                  # Every day at midnight
  # schedule = "*-*-01,15 03:00:00";    # 1st and 15th at 3am
  # schedule = null;                     # No automatic runs (manual only)
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
  
  [radarr]
  url = "http://localhost:7878"
  api_key = "your-api-key"
  
  [qbittorrent]
  url = "http://localhost:8080"
  username = "admin"
  password = "your-password"
  
  [notifications]
  discord_webhook = "https://discord.com/api/webhooks/..."
  
  [outputs]
  report_dir = "/var/lib/auditarr/reports"
  
  [permissions]
  enabled = true
  group_gid = 1000
  allowed_uids = [1001, 1002, 1003, 1004, 1005]
'';
```

### Operations

```bash
# Trigger manual run
sudo systemctl start auditarr

# Check next scheduled run
sudo systemctl list-timers auditarr

# View logs
sudo journalctl -u auditarr -n 100 -f

# List reports
ls -la /var/lib/auditarr/reports/

# View latest report
cat /var/lib/auditarr/reports/$(ls -t /var/lib/auditarr/reports/ | head -1)
```

## CI/CD

The project uses GitHub Actions to:
1. Run tests on every push
2. Lint with golangci-lint
3. Auto-increment version tag on merge to main
4. Create GitHub releases
5. Build and verify Nix flake

To manually trigger a release, push to main or create a tag:
```bash
git tag v0.1.0
git push origin v0.1.0
```

## Development

```bash
# Enter dev shell
nix develop

# Run tests
go test ./...

# Build binary
go build -o auditarr ./cmd/auditarr

# Run with example config
cp config.example.toml config.toml
# Edit config.toml with your settings
./auditarr scan --config=./config.toml --verbose
```

## License

MIT
