tenable-exposure-bot
=====================

What
----
A small multi-agent prototype that queries Tenable exports (vulnerabilities, assets) and uses a Google ADK-based agent layer to summarize and orchestrate responses.

Why
---
This repo demonstrates an orchestration layer for exposure management where agents can call deterministic tools (Tenable export endpoints) and produce human-friendly summaries.

Quick start
-----------
1. Create and activate a virtual environment (PowerShell example):

```powershell
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
```

Or in Git Bash (MINGW64):

```bash
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
```

2. Create a `.env` file with keys (example):

```
GOOGLE_API_KEY=your_gemini_key
TENABLE_ACCESS_KEY=your_tenable_access_key
TENABLE_SECRET_KEY=your_tenable_secret_key
OPENAI_API_KEY=...   # optional
ANTHROPIC_API_KEY=... # optional
```

3. Run the main demo:

```bash
python main.py
```

Notes & next steps
------------------
- The code includes a fallback when Tenable rejects server-side tag filters: the export is retried without tag filters and results are filtered locally. This is robust but may pull more data.
- The agent/tool function signatures have defaults set inside functions to avoid function-declaration schema warnings from the ADK.
- Improve logging, add unit tests for Tenable payload building and local filter behavior, and add rate-limit/backoff for larger exports.

Contributing
------------
Happy to help expand: add a config module, implement caching/pagination, or wire a small web UI.
