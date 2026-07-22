"""Central configuration for the LinkX support-desk testbed.

Values here are intentionally simple (no external secrets) because this is a
self-contained, reproducible benchmark environment, not a production service.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Root of the repo (…/linkx-testbed)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Load secrets (ANTHROPIC_API_KEY etc.) from a gitignored .env at the repo root.
# Loaded here because every entry point imports this module early: the API
# directly, and the agent chain via `app.db`. An existing shell env var wins
# over the .env value (override=False), so `export` still takes precedence.
load_dotenv(BASE_DIR / ".env", override=False)

# Primary database file and the snapshot used for per-trial reset.
DB_PATH = Path(os.environ.get("LINKX_DB", DATA_DIR / "linkx.db"))
SNAPSHOT_PATH = DATA_DIR / "linkx.snapshot.db"
DB_URL = f"sqlite:///{DB_PATH}"

# Deterministic seed so the synthetic dataset is byte-for-byte reproducible
# across machines and runs. This matters for comparing ASR across models and
# topologies later.
RANDOM_SEED = int(os.environ.get("LINKX_SEED", "6727"))

# Default dataset volume. Small on purpose: the benchmark needs scenario
# coverage, not scale.
N_CUSTOMERS = int(os.environ.get("LINKX_N_CUSTOMERS", "200"))