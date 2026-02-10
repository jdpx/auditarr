package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jdpx/auditarr/internal/analysis"
)

type DiscordNotifier struct {
	webhookURL string
	client     *http.Client
}

func NewDiscordNotifier(webhookURL string) *DiscordNotifier {
	return &DiscordNotifier{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (dn *DiscordNotifier) Send(result *analysis.AnalysisResult, reportPath string, duration time.Duration) error {
	if dn.webhookURL == "" {
		return nil
	}

	color := 3447003
	if result.Summary.OrphanCount > 0 || result.Summary.PermissionErrors > 0 {
		color = 15158332
	} else if result.Summary.AtRiskCount > 0 || result.Summary.PermissionWarnings > 0 {
		color = 16776960
	}

	summaryValue := fmt.Sprintf(
		"✅ %d healthy (tracked + hardlinked)\n⚠️ %d at risk (tracked, NOT hardlinked)\n❌ %d orphaned (not tracked)\n🚨 %d suspicious file(s)",
		result.Summary.HealthyCount,
		result.Summary.AtRiskCount,
		result.Summary.OrphanCount,
		result.Summary.SuspiciousCount,
	)

	if result.Summary.PermissionErrors+result.Summary.PermissionWarnings > 0 {
		summaryValue += fmt.Sprintf("\n⚠️ %d permission issue(s)", result.Summary.PermissionErrors+result.Summary.PermissionWarnings)
	}

	payload := map[string]interface{}{
		"content": nil,
		"embeds": []map[string]interface{}{
			{
				"title": "Media Audit Complete",
				"color": color,
				"fields": []map[string]interface{}{
					{
						"name":   "Summary",
						"value":  summaryValue,
						"inline": false,
					},
					{
						"name":   "Report Location",
						"value":  reportPath,
						"inline": false,
					},
				},
				"footer": map[string]interface{}{
					"text": fmt.Sprintf("Duration: %.1fs", duration.Seconds()),
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := dn.client.Post(dn.webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
