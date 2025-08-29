@echo off
echo Running PII Detection and Redaction Solution
python pii_detector.py iscp_pii_dataset_-_Sheet1.csv
echo Solution completed. Output: redacted_output_iscp_pii_dataset_-_Sheet1.csv
pause
