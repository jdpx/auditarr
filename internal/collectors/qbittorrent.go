package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jdpx/auditarr/internal/models"
)

type QBCollector struct {
	client   *http.Client
	baseURL  string
	username string
	password string
	cookie   string
	mu       sync.Mutex
}

func NewQBCollector(baseURL, username, password string) *QBCollector {
	return &QBCollector{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:  baseURL,
		username: username,
		password: password,
	}
}

func (qbc *QBCollector) Name() string {
	return "qbittorrent"
}

func (qbc *QBCollector) Collect(ctx context.Context) ([]models.Torrent, error) {
	if qbc.baseURL == "" {
		return nil, nil
	}

	if err := qbc.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	torrents, err := qbc.fetchTorrents(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch torrents: %w", err)
	}

	var result []models.Torrent
	for _, t := range torrents {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		files, err := qbc.fetchTorrentFiles(ctx, t.Hash)
		if err != nil {
			fmt.Printf("Warning: failed to fetch files for torrent %s: %v\n", t.Hash, err)
		}

		completedOn := time.Time{}
		if t.CompletionOn > 0 {
			completedOn = time.Unix(t.CompletionOn, 0)
		}

		result = append(result, models.Torrent{
			Hash:        t.Hash,
			Name:        t.Name,
			SavePath:    t.SavePath,
			State:       mapQBState(t.State),
			CompletedOn: completedOn,
			Files:       files,
		})
	}

	return result, nil
}

func (qbc *QBCollector) authenticate(ctx context.Context) error {
	qbc.mu.Lock()
	defer qbc.mu.Unlock()

	if qbc.cookie != "" {
		return nil
	}

	authURL := fmt.Sprintf("%s/api/v2/auth/login", qbc.baseURL)
	data := url.Values{}
	data.Set("username", qbc.username)
	data.Set("password", qbc.password)

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := qbc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("authentication failed with status %d", resp.StatusCode)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "SID" {
			qbc.cookie = cookie.Value
			break
		}
	}

	_, _ = io.Copy(io.Discard, resp.Body)

	if qbc.cookie == "" {
		return fmt.Errorf("no session cookie received")
	}

	return nil
}

func (qbc *QBCollector) fetchTorrents(ctx context.Context) ([]qbTorrent, error) {
	qbc.mu.Lock()
	cookie := qbc.cookie
	qbc.mu.Unlock()

	url := fmt.Sprintf("%s/api/v2/torrents/info", qbc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Cookie", fmt.Sprintf("SID=%s", cookie))
	req.Header.Set("Accept", "application/json")

	resp, err := qbc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		qbc.mu.Lock()
		qbc.cookie = ""
		qbc.mu.Unlock()
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("session expired")
	}

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var torrents []qbTorrent
	if err := json.NewDecoder(resp.Body).Decode(&torrents); err != nil {
		return nil, err
	}

	return torrents, nil
}

func (qbc *QBCollector) fetchTorrentFiles(ctx context.Context, hash string) ([]string, error) {
	qbc.mu.Lock()
	cookie := qbc.cookie
	qbc.mu.Unlock()

	url := fmt.Sprintf("%s/api/v2/torrents/files?hash=%s", qbc.baseURL, hash)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Cookie", fmt.Sprintf("SID=%s", cookie))
	req.Header.Set("Accept", "application/json")

	resp, err := qbc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var files []qbFile
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}

	var paths []string
	for _, f := range files {
		paths = append(paths, f.Name)
	}

	return paths, nil
}

func mapQBState(state string) models.TorrentState {
	switch state {
	case "downloading", "metaDL", "allocating":
		return models.StateDownloading
	case "checkingUP", "checkingDL":
		return models.StateChecking
	case "uploading", "pausedUP":
		return models.StateCompleted
	case "pausedDL":
		return models.StatePaused
	case "stalledUP", "stalledDL":
		return models.StateStalled
	default:
		return models.StateCompleted
	}
}

type qbTorrent struct {
	Hash         string `json:"hash"`
	Name         string `json:"name"`
	State        string `json:"state"`
	SavePath     string `json:"save_path"`
	CompletionOn int64  `json:"completion_on"`
}

type qbFile struct {
	Name string `json:"name"`
}
