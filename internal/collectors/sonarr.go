package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jdpx/auditarr/internal/models"
)

type SonarrCollector struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

func NewSonarrCollector(baseURL, apiKey string) *SonarrCollector {
	return &SonarrCollector{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

func (sc *SonarrCollector) Name() string {
	return "sonarr"
}

func (sc *SonarrCollector) Collect(ctx context.Context) ([]models.ArrFile, error) {
	if sc.baseURL == "" {
		return nil, nil
	}

	var arrFiles []models.ArrFile

	seriesList, err := sc.fetchSeries(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch series: %w", err)
	}

	for _, series := range seriesList {
		select {
		case <-ctx.Done():
			return arrFiles, ctx.Err()
		default:
		}

		episodeFiles, err := sc.fetchEpisodeFiles(ctx, series.ID)
		if err != nil {
			fmt.Printf("Warning: failed to fetch episode files for series %d: %v\n", series.ID, err)
			continue
		}

		for _, ef := range episodeFiles {
			arrFiles = append(arrFiles, models.ArrFile{
				Path:       ef.Path,
				SeriesID:   series.ID,
				EpisodeID:  ef.ID,
				Monitored:  ef.Monitored,
				ImportDate: ef.DateAdded,
			})
		}
	}

	return arrFiles, nil
}

func (sc *SonarrCollector) fetchSeries(ctx context.Context) ([]sonarrSeries, error) {
	url := fmt.Sprintf("%s/api/v3/series", sc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Api-Key", sc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var series []sonarrSeries
	if err := json.NewDecoder(resp.Body).Decode(&series); err != nil {
		return nil, err
	}

	return series, nil
}

func (sc *SonarrCollector) fetchEpisodeFiles(ctx context.Context, seriesID int) ([]sonarrEpisodeFile, error) {
	url := fmt.Sprintf("%s/api/v3/episodefile?seriesId=%d", sc.baseURL, seriesID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Api-Key", sc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var files []sonarrEpisodeFile
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}

	return files, nil
}

type sonarrSeries struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Monitored bool   `json:"monitored"`
}

type sonarrEpisodeFile struct {
	ID        int       `json:"id"`
	SeriesID  int       `json:"seriesId"`
	Path      string    `json:"path"`
	Monitored bool      `json:"monitored"`
	DateAdded time.Time `json:"dateAdded"`
}
