package collectors

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// httpRetryAttempts is how many times an idempotent request is tried before
// giving up. Transient API failures — a network blip or an HTTP 5xx such as a
// momentary SQLite contention while scanning many items back-to-back — are
// retried with a short backoff.
const httpRetryAttempts = 3

// doWithRetry runs an idempotent request, rebuilt fresh by newReq on each
// attempt, retrying on network errors or HTTP 5xx with a short linear backoff.
// Non-5xx responses (2xx/4xx) are returned to the caller to handle, and the
// caller owns closing the response body. The backoff respects ctx cancellation.
func doWithRetry(ctx context.Context, client *http.Client, newReq func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= httpRetryAttempts; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		switch {
		case err != nil:
			lastErr = err
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("API returned status %d", resp.StatusCode)
			resp.Body.Close()
		default:
			return resp, nil
		}

		if attempt < httpRetryAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*250) * time.Millisecond):
			}
		}
	}
	return nil, lastErr
}
