#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out
python3 fetch_data.py
python3 evaluate.py
python3 evaluate_clean.py
python3 evaluate_hard_negatives.py
python3 evaluate_split_custom.py
python3 evaluate_concurrent_sessions.py
if command -v gitleaks >/dev/null && command -v trufflehog >/dev/null; then
  python3 compare_scanners_n300.py
else
  echo "Gitleaks/TruffleHog yok; compare_scanners_n300.py atlandı."
fi
echo "Raporlar: out/"
