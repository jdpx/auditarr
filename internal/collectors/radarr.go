package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jdpx/auditarr/internal/models"
)

type RadarrCollector struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

func NewRadarrCollector(baseURL, apiKey string) *RadarrCollector {
	return &RadarrCollector{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

func (rc *RadarrCollector) Name() string {
	return "radarr"
}

func (rc *RadarrCollector) Collect(ctx context.Context) ([]models.ArrFile, error) {
	if rc.baseURL == "" {
		return nil, nil
	}

	var arrFiles []models.ArrFile

	movies, err := rc.fetchMovies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch movies: %w", err)
	}

	for _, movie := range movies {
		select {
		case <-ctx.Done():
			return arrFiles, ctx.Err()
		default:
		}

		movieFiles, err := rc.fetchMovieFiles(ctx, movie.ID)
		if err != nil {
			fmt.Printf("Warning: failed to fetch movie files for movie %d: %v\n", movie.ID, err)
			continue
		}

		for _, mf := range movieFiles {
			arrFiles = append(arrFiles, models.ArrFile{
				Path:       mf.Path,
				MovieID:    movie.ID,
				Monitored:  movie.Monitored,
				ImportDate: mf.DateAdded,
			})
		}
	}

	return arrFiles, nil
}

func (rc *RadarrCollector) fetchMovies(ctx context.Context) ([]radarrMovie, error) {
	url := fmt.Sprintf("%s/api/v3/movie", rc.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Api-Key", rc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var movies []radarrMovie
	if err := json.NewDecoder(resp.Body).Decode(&movies); err != nil {
		return nil, err
	}

	return movies, nil
}

func (rc *RadarrCollector) fetchMovieFiles(ctx context.Context, movieID int) ([]radarrMovieFile, error) {
	url := fmt.Sprintf("%s/api/v3/moviefile?movieId=%d", rc.baseURL, movieID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Api-Key", rc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var files []radarrMovieFile
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}

	return files, nil
}

type radarrMovie struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Monitored bool   `json:"monitored"`
}

type radarrMovieFile struct {
	ID        int       `json:"id"`
	MovieID   int       `json:"movieId"`
	Path      string    `json:"path"`
	DateAdded time.Time `json:"dateAdded"`
}
