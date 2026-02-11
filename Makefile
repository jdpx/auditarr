# Download latest auditarr report from louise NAS
# Usage: make fetch-report
fetch-report:
	@echo "Fetching latest auditarr report from louise..."
	@mkdir -p reports
	@ssh -q nas-louise 'cat $$(ls -t /var/lib/auditarr/reports/*.md | head -1)' > reports/auditarr-report-latest.md
	@echo "Downloaded: reports/auditarr-report-latest.md"
