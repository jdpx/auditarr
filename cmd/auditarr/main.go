package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jdpx/auditarr/internal/analysis"
	"github.com/jdpx/auditarr/internal/collectors"
	"github.com/jdpx/auditarr/internal/config"
	"github.com/jdpx/auditarr/internal/models"
	"github.com/jdpx/auditarr/internal/reporting"
	"github.com/jdpx/auditarr/internal/utils"
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
	verbose := fs.Bool("verbose", false, "Enable verbose output")
	skipPermissions := fs.Bool("skip-permissions", false, "Skip permission auditing")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, shutting down...")
		cancel()
	}()

	startTime := time.Now()

	if *verbose {
		fmt.Println("Starting media audit...")
	}

	fsCollector := collectors.NewFilesystemCollector(cfg.Paths.MediaRoot)

	if *verbose {
		fmt.Println("Collecting filesystem data...")
	}

	mediaFiles, err := fsCollector.Collect(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to collect filesystem data: %v\n", err)
	}

	if *verbose {
		fmt.Printf("Found %d media files\n", len(mediaFiles))
	}

	var permissions []models.FilePermissions
	if cfg.Permissions.Enabled && !*skipPermissions {
		if *verbose {
			fmt.Println("Collecting permission data...")
		}
		permissions, err = utils.CollectPermissions(cfg.Paths.MediaRoot, cfg.Permissions.SkipPaths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to collect permission data: %v\n", err)
		} else if *verbose {
			fmt.Printf("Collected permissions for %d files\n", len(permissions))
		}
	}

	var sonarrFiles, radarrFiles []models.ArrFile
	var connectionStatus []analysis.ServiceStatus

	if cfg.Sonarr.URL != "" {
		sonarrCollector := collectors.NewSonarrCollector(cfg.Sonarr.URL, cfg.Sonarr.APIKey)
		sonarrStatus := analysis.ServiceStatus{Name: "Sonarr", Enabled: true}
		if err := sonarrCollector.TestConnection(ctx); err != nil {
			sonarrStatus.OK = false
			sonarrStatus.Error = err.Error()
			fmt.Fprintf(os.Stderr, "[SONARR] Connection failed: %v\n", err)
		} else {
			sonarrStatus.OK = true
			fmt.Println("[SONARR] Connected successfully")
		}
		connectionStatus = append(connectionStatus, sonarrStatus)
		if *verbose {
			fmt.Println("Collecting Sonarr data...")
		}
		sonarrFiles, err = sonarrCollector.Collect(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to collect Sonarr data: %v\n", err)
		} else if *verbose {
			fmt.Printf("Found %d Sonarr files\n", len(sonarrFiles))
		}
	}

	if cfg.Radarr.URL != "" {
		radarrCollector := collectors.NewRadarrCollector(cfg.Radarr.URL, cfg.Radarr.APIKey)
		radarrStatus := analysis.ServiceStatus{Name: "Radarr", Enabled: true}
		if err := radarrCollector.TestConnection(ctx); err != nil {
			radarrStatus.OK = false
			radarrStatus.Error = err.Error()
			fmt.Fprintf(os.Stderr, "[RADARR] Connection failed: %v\n", err)
		} else {
			radarrStatus.OK = true
			fmt.Println("[RADARR] Connected successfully")
		}
		connectionStatus = append(connectionStatus, radarrStatus)
		if *verbose {
			fmt.Println("Collecting Radarr data...")
		}
		radarrFiles, err = radarrCollector.Collect(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to collect Radarr data: %v\n", err)
		} else if *verbose {
			fmt.Printf("Found %d Radarr files\n", len(radarrFiles))
		}
	}

	var torrents []models.Torrent
	if cfg.Qbittorrent.URL != "" {
		qbStatus := analysis.ServiceStatus{Name: "qBittorrent", Enabled: true}
		if *verbose {
			fmt.Println("Collecting qBittorrent data...")
		}
		qbCollector := collectors.NewQBCollector(cfg.Qbittorrent.URL, cfg.Qbittorrent.Username, cfg.Qbittorrent.Password)
		torrents, err = qbCollector.Collect(ctx)
		if err != nil {
			qbStatus.OK = false
			qbStatus.Error = err.Error()
			fmt.Fprintf(os.Stderr, "Warning: failed to collect qBittorrent data: %v\n", err)
		} else {
			qbStatus.OK = true
		}
		connectionStatus = append(connectionStatus, qbStatus)
		if *verbose {
			fmt.Printf("Found %d torrents\n", len(torrents))
		}
	}

	if *verbose {
		fmt.Println("Analyzing data...")
	}

	engine := analysis.NewEngine(
		cfg.Sonarr.GraceHours,
		cfg.Radarr.GraceHours,
		cfg.Qbittorrent.GraceHours,
		cfg.Suspicious.Extensions,
		cfg.Suspicious.FlagArchives,
		cfg.Permissions.Enabled && !*skipPermissions,
		cfg.Permissions.GroupGID,
		cfg.Permissions.AllowedUIDs,
		cfg.Permissions.SGIDPaths,
		cfg.Permissions.SkipPaths,
		cfg.Permissions.NonstandardSeverity,
		cfg.PathMappings,
	)

	result := engine.Analyze(mediaFiles, sonarrFiles, radarrFiles, torrents, permissions)
	result.ConnectionStatus = connectionStatus

	duration := time.Since(startTime)
	result.Summary.Duration = duration

	formatter := reporting.NewMarkdownFormatter()
	reportContent := formatter.Format(result, cfg, duration)

	reportDir := cfg.GetReportPath()
	reportPath, err := formatter.WriteToFile(reportContent, reportDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write report: %v\n", err)
	} else {
		fmt.Printf("Report written to: %s\n", reportPath)
	}

	notifier := reporting.NewDiscordNotifier(cfg.Notifications.DiscordWebhook)
	if err := notifier.Send(result, reportPath, duration); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to send notification: %v\n", err)
	}

	fmt.Printf("Audit complete in %.2f seconds\n", duration.Seconds())
	fmt.Printf("Results: %d healthy, %d at risk, %d orphaned, %d suspicious\n",
		result.Summary.HealthyCount,
		result.Summary.AtRiskCount,
		result.Summary.OrphanCount,
		result.Summary.SuspiciousCount,
	)

	if result.Summary.OrphanCount > 0 || result.Summary.AtRiskCount > 0 {
		os.Exit(2)
	}
}
