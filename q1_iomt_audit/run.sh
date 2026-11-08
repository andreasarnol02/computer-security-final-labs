#!/usr/bin/env bash
# Satu perintah: jalankan seluruh skenario audit IoMT di dalam satu kontainer
# network-isolated, dan rekam semuanya ke run_output.txt.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker ${LAB_DOCKER_CONTEXT:+--context "$LAB_DOCKER_CONTEXT"} run --rm --network none -v "$PWD:/lab" -w /lab final-lab:1 bash scenario.sh 2>&1 | tee run_output.txt
