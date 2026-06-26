#!/usr/bin/env bash
# Sentinel CTI — one-command launcher.
#   ./run.sh            start with the local LLM (Ollama) if available
#   CTI_LLM=0 ./run.sh  fast heuristics mode (no model needed)
#
# Ensures Ollama is serving (when installed), then starts the dashboard.
set -u
cd "$(dirname "$0")"

# Start Ollama if it's installed but not already responding.
if command -v ollama >/dev/null 2>&1; then
  if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "[run] starting Ollama..."
    nohup ollama serve >/tmp/ollama.log 2>&1 &
    for _ in $(seq 1 15); do
      curl -s http://localhost:11434/api/tags >/dev/null 2>&1 && break
      sleep 1
    done
  fi
else
  echo "[run] Ollama not found — running in heuristics mode."
  export CTI_LLM=0
fi

echo "[run] starting dashboard on http://127.0.0.1:8077 (Ctrl+C to stop)"
exec python3 -m cti_agent.server
