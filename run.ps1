<#
.SYNOPSIS
    FalkorDB "Graph Hacks" Hackathon - Windows PowerShell Zero-Touch Orchestrator
.DESCRIPTION
    Native PowerShell CLI equivalent to Makefile for cross-platform judge evaluation.
    Usage:
        .\run.ps1 install
        .\run.ps1 up
        .\run.ps1 init-db
        .\run.ps1 train
        .\run.ps1 train-self-play
        .\run.ps1 federated
        .\run.ps1 forensics
        .\run.ps1 serve
        .\run.ps1 demo
        .\run.ps1 clean
#>

param (
    [Parameter(Position=0)]
    [ValidateSet("help", "install", "up", "down", "init-db", "train", "train-self-play", "federated", "forensics", "serve", "demo", "clean")]
    [string]$Target = "help"
)

function Show-Help {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  FALKORDB AUTONOMOUS APT HUNTING GRAPH-AGENT // POWERSHELL RUNNER" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  .\run.ps1 install         Install all Python dependencies"
    Write-Host "  .\run.ps1 up              Spin up FalkorDB and infrastructure via Docker"
    Write-Host "  .\run.ps1 down            Stop and remove containerized infrastructure"
    Write-Host "  .\run.ps1 init-db         Populate 50-node enterprise graph & APT path"
    Write-Host "  .\run.ps1 train           Train Dueling DQN with SSD Replay Buffer"
    Write-Host "  .\run.ps1 train-self-play Run AlphaSec Red vs Blue Adversarial Self-Play"
    Write-Host "  .\run.ps1 federated       Simulate Cross-Tenant FedAvg privacy aggregation"
    Write-Host "  .\run.ps1 forensics       Generate AI CISO Incident Response report"
    Write-Host "  .\run.ps1 serve           Launch FastAPI Serving Gateway (port 8000)"
    Write-Host "  .\run.ps1 demo            Execute end-to-end deterministic judge demo"
    Write-Host "  .\run.ps1 clean           Purge temp files and SSD replay buffer mmaps"
    Write-Host "======================================================================" -ForegroundColor Cyan
}

switch ($Target) {
    "help" {
        Show-Help
    }
    "install" {
        Write-Host "[*] Installing Python dependencies..." -ForegroundColor Green
        pip install -r requirements.txt
    }
    "up" {
        Write-Host "[*] Starting FalkorDB and Enterprise Infrastructure..." -ForegroundColor Green
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            docker run -d --name falkordb-apt -p 6379:6379 -it --rm falkordb/falkordb:latest
            Write-Host "[+] FalkorDB running in RAM on localhost:6379" -ForegroundColor Green
        } else {
            Write-Host "[!] Docker not found in PATH. Standalone in-memory fallback active." -ForegroundColor Yellow
        }
    }
    "down" {
        Write-Host "[*] Stopping containerized infrastructure..." -ForegroundColor Yellow
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            docker stop falkordb-apt
        }
    }
    "init-db" {
        Write-Host "[*] Initializing FalkorDB schema and 50-node synthetic enterprise topology..." -ForegroundColor Green
        python database.py
    }
    "train" {
        Write-Host "[*] Launching Dueling Double DQN training with SSD-backed replay buffer..." -ForegroundColor Green
        python train.py
    }
    "train-self-play" {
        Write-Host "[*] Launching AlphaSec Adversarial Self-Play (Red vs. Blue)..." -ForegroundColor Green
        python self_play_env.py
    }
    "federated" {
        Write-Host "[*] Executing Cross-Tenant Privacy-Preserving Federated Learning (FedAvg)..." -ForegroundColor Green
        python federated_server.py
    }
    "forensics" {
        Write-Host "[*] Synthesizing Generative Incident Response Report (LLM Graph RAG)..." -ForegroundColor Green
        python gen_forensics.py
    }
    "serve" {
        Write-Host "[*] Launching FastAPI High-Frequency Inference Gateway on port 8000..." -ForegroundColor Green
        python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
    }
    "demo" {
        Write-Host "[*] Running Deterministic End-to-End Evaluation Demo for Judges..." -ForegroundColor Cyan
        python demo.py
    }
    "clean" {
        Write-Host "[*] Cleaning temporary files and buffers..." -ForegroundColor Yellow
        Remove-Item -Path "buffer_ssd_storage\*.dat" -Force -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force -Path "**/__pycache__" -ErrorAction SilentlyContinue
        Write-Host "[+] Clean complete." -ForegroundColor Green
    }
}
