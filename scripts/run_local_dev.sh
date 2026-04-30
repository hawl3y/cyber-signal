#!/usr/bin/env bash
set -e
source .venv/bin/activate
export RUN_SCHEDULER=true
python run.py