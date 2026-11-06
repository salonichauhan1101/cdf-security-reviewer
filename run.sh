#!/bin/bash
# Usage: ./run.sh <path-to-source-folder> [app name]
set -e
python reviewer.py "$1"
python report.py verified_findings.json "${2:-$(basename "$1")}"
