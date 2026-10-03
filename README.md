# TrustGuard — "Think Before You Click"

A privacy-first security assistant that analyzes suspicious URLs and messages and returns
**Risk → Reason → Evidence → Recommended action**.

## Quick start (demo)

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Open **http://localhost:8000** — paste a suspicious URL or message and hit **ANALYZE**.
The web UI is served by the app itself (no separate frontend server needed).

Interactive API docs: http://localhost:8000/docs · Health check: `/health`

## Analyze via API

```bash
curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" \
  -d '{"text": "https://sbi-secure-login.xyz/verify-account"}'
```

## Architecture (MVP)

- `engine/url_analyzer.py` — heuristic URL signals (brand mismatch incl. leet lookalikes,
  suspicious TLDs, credential-bait keywords, punycode/homoglyphs, IP hosts, shorteners,
  userinfo tricks, odd ports, ...)
- `engine/message_analyzer.py` — social-engineering patterns (urgency, threats,
  credential requests, rewards, authority claims, embedded links — which are also scored
  through the URL analyzer), English + Hinglish/Devanagari
- `engine/regexes.py` — shared URL regex (single source of truth)
- `engine/scoring.py` — deterministic risk score (rules decide the score, never an LLM)
- `engine/report.py` — unified report: score, level, signals, recommended actions
- `main.py` — FastAPI server: web UI at `/`, API at `/analyze`, health at `/health`
- `static/index.html` — markup-only demo shell (no build step)
- `static/styles.css` — all styling, design tokens and animations
- `static/app.js` — matrix rain, cursor, scroll reveals, analyze/render
- `static/logo.svg` — shield mark (also used as the favicon)

## Roadmap

1. ✅ Detection engine + deterministic scoring
2. ✅ Web demo UI
3. LLM explanation layer (AI explains the score; rules still determine it)
4. QR-code decoding from uploaded screenshots
5. Threat-intel integrations (Google Safe Browsing, VirusTotal, WHOIS) — optional enhancers

## Tests

```bash
pytest tests/ -q
```
"# Trustguard" 
"# Trustguard" 
"# TrustGuard" 
