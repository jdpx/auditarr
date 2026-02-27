# Download latest auditarr report from louise NAS
# Usage: make fetch-report
fetch-report:
	@echo "Fetching latest auditarr report from louise..."
	@mkdir -p reports
	@ssh -q nas-louise 'cat $$(ls -t /var/lib/auditarr/reports/*.md | head -1)' > reports/auditarr-report-latest.md
	@echo "Downloaded: reports/auditarr-report-latest.md"

# Download latest JSON report (for scripting)
# Usage: make fetch-json
fetch-json:
	@echo "Fetching latest auditarr JSON report from louise..."
	@mkdir -p reports
	@ssh -q nas-louise 'cat $$(ls -t /var/lib/auditarr/reports/*.json | head -1)' > reports/auditarr-report-latest.json
	@echo "Downloaded: reports/auditarr-report-latest.json"

# Download both Markdown and JSON reports
# Usage: make fetch-reports
fetch-reports: fetch-report fetch-json

# Fetch JSON and extract orphaned files list for script processing
# Usage: make orphan-files
orphan-files: fetch-json
	@cat reports/auditarr-report-latest.json | jq -r '.orphaned_media[].path' > reports/orphan-files.txt
	@echo "Extracted $$(wc -l < reports/orphan-files.txt) orphaned file paths to: reports/orphan-files.txt"

# Fetch and show summary from JSON
# Usage: make report-summary
report-summary: fetch-json
	@cat reports/auditarr-report-latest.json | jq '{generated_at, duration_seconds, summary}'
