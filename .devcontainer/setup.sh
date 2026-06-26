#!/usr/bin/env bash
# One-time Codespace provisioning: Python deps + local Ollama model.
# Designed to never fail the build — if the model can't be pulled, the app
# still runs in heuristics mode (CTI_LLM=0).
set -u

echo "[setup] Installing Python dependencies..."
pip3 install -r requirements.txt || echo "[setup] pip install had issues"

echo "[setup] Installing system dependencies..."
sudo apt-get update && sudo apt-get install -y zstd || {
  echo "[setup] apt install failed — Ollama may not install."
}

echo "[setup] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh || {
  echo "[setup] Ollama install failed — app will run in heuristics mode."
  exit 0
}

echo "[setup] Verifying Ollama installed..."
which ollama && ollama --version || {
  echo "[setup] Ollama binary not found after install."
  exit 0
}

echo "[setup] Starting Ollama..."
nohup ollama serve >/tmp/ollama.log 2>&1 &
for i in $(seq 1 30); do
  curl -s http://localhost:11434/api/tags >/dev/null 2>&1 && break
  sleep 2
done

echo "[setup] Pulling phi3 model (one-time, ~2GB)..."
ollama pull phi3 || echo "[setup] model pull skipped — run 'ollama pull phi3' later, or use CTI_LLM=0."

echo "[setup] Done."
echo "[setup] Start the app with:  python3 -m cti_agent.server"
