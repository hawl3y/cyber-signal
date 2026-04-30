#!/usr/bin/env bash
set -e
source .venv/bin/activate
export RUN_SCHEDULER=true
gunicorn --bind 0.0.0.0:5001 --reload "app:create_app()"