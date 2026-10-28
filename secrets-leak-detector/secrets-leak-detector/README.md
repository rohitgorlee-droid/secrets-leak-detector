# Secrets Leak Detector

A simple base tool that scans files and directories for hard-coded secrets
(API keys, tokens, private keys, passwords) using regex rules plus a
Shannon-entropy check. Python 3.9+, standard library only.

## Usage

    python secrets_leak_detector.py .
    python secrets_leak_detector.py src/ config/ --format json --output report.json
    python secrets_leak_detector.py . --fail-on high

## Notes

- Matched secrets are masked in reports.
- Add `# nosecret` to a line to suppress findings on it.
- Exit code 1 when findings meet the `--fail-on` severity (default: medium).
- Add new detection rules to the `RULES` list.
