#!/bin/bash

set -e

if command -v python3 &> /dev/null; then
  PYTHON="python3"
elif command -v python &> /dev/null; then
  PYTHON="python"
else
  echo "Error: Python is not installed."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment using $PYTHON..."
  "$PYTHON" -m venv .venv
fi

echo "Installing dependencies..."
.venv/bin/pip install -r requirements.txt

echo "Setup complete! Run 'source .venv/bin/activate' in your terminal to activate."
