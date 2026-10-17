# ==============================================================================
# FALKORDB "GRAPH HACKS" HACKATHON - ZERO-TOUCH ORCHESTRATION MAKEFILE
# Planetary-Scale Autonomous APT Hunting Graph-Agent
# ==============================================================================

SHELL := /bin/bash
PYTHON := python
PIP := pip
DOCKER := docker
COMPOSE := docker compose

.PHONY: all help install up down init-db train train-self-play federated forensics serve demo test clean

help:
	@echo "======================================================================"
	@echo "  FALKORDB AUTONOMOUS APT HUNTING GRAPH-AGENT // BUILD SYSTEM"
	@echo "======================================================================"
	@echo "  make install         Install all Python dependencies & pre-requisites"
	@echo "  make up              Spin up FalkorDB and infrastructure via Docker"
	@echo "  make down            Stop and remove containerized infrastructure"
	@echo "  make init-db         Populate 50-node enterprise graph & APT path"
	@echo "  make train           Train Dueling DQN with SSD Replay Buffer (1,000 ep)"
	@echo "  make train-self-play Run AlphaSec Red vs Blue Adversarial Self-Play"
	@echo "  make federated       Simulate Cross-Tenant FedAvg privacy aggregation"
	@echo "  make forensics       Generate AI CISO Incident Response report (Gemini)"
	@echo "  make serve           Launch FastAPI Serving Gateway (port 8000)"
	@echo "  make demo            Execute end-to-end deterministic judge demo"
	@echo "  make clean           Purge temp files, caches, and SSD replay mmaps"
	@echo "======================================================================"

install:
	@echo "[*] Installing Python core dependencies..."
	$(PIP) install -r requirements.txt
	@echo "[+] Core dependencies installed successfully."

up:
	@echo "[*] Starting FalkorDB and Enterprise Infrastructure..."
	@if command -v docker >/dev/null 2>&1; then \
		$(DOCKER) run -d --name falkordb-apt -p 6379:6379 -it --rm falkordb/falkordb:latest || true; \
		echo "[+] FalkorDB running in RAM on localhost:6379"; \
	else \
		echo "[!] Docker not detected in PATH. Standalone in-memory fallback enabled."; \
	fi

down:
	@echo "[*] Stopping containerized infrastructure..."
	@if command -v docker >/dev/null 2>&1; then \
		$(DOCKER) stop falkordb-apt || true; \
		echo "[+] FalkorDB container stopped."; \
	fi

init-db:
	@echo "[*] Initializing FalkorDB schema and 50-node synthetic enterprise topology..."
	$(PYTHON) database.py

train:
	@echo "[*] Launching Dueling Double DQN training with SSD-backed replay buffer..."
	$(PYTHON) train.py

train-self-play:
	@echo "[*] Launching AlphaSec Adversarial Self-Play (Red vs. Blue)..."
	$(PYTHON) self_play_env.py

federated:
	@echo "[*] Executing Cross-Tenant Privacy-Preserving Federated Learning (FedAvg)..."
	$(PYTHON) federated_server.py

forensics:
	@echo "[*] Synthesizing Generative Incident Response Report (LLM Graph RAG)..."
	$(PYTHON) gen_forensics.py

serve:
	@echo "[*] Launching FastAPI High-Frequency Inference Gateway on port 8000..."
	$(PYTHON) -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

demo:
	@echo "[*] Running Deterministic End-to-End Evaluation Demo for Judges..."
	$(PYTHON) demo.py

clean:
	@echo "[*] Cleaning temporary artifacts, checkpoints, and replay buffers..."
	@rm -rf buffer_ssd_storage/*.dat
	@rm -rf __pycache__ */__pycache__
	@echo "[+] Clean complete."
