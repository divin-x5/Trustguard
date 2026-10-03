"""TrustGuard API server."""
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from engine import analyze_url, analyze_message, build_report
from engine.regexes import URL_RE
import re

app = FastAPI(title="TrustGuard", version="0.1.0",
              description="Think Before You Click — privacy-first scam analysis")

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000,
                      description="URL or message text to analyze",
                      examples=["https://sbi-secure-login.xyz/verify-account",
                                "URGENT! Your account will be blocked. Share your OTP at http://sbi-login.xyz"])

    @field_validator("text")
    @classmethod
    def text_must_be_analyzable(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Please paste a URL or message to analyze")
        if not any(c.isalnum() for c in v):
            raise ValueError("Input contains no analyzable content")
        return v


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api-info")
def api_info():
    return {"name": "TrustGuard", "version": "0.1.0", "endpoints": ["/analyze", "/health"]}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    text = req.text.strip()
    if _looks_like_url(text) or ("://" in text and not URL_RE.sub("", text).strip()):
        analysis = analyze_url(text)
    else:
        # Free text, with or without embedded links -> message analysis
        # (the message analyzer also flags any links it contains).
        analysis = analyze_message(text)
    return build_report(analysis)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Never leak a stack trace to the client during a demo
    return JSONResponse(status_code=500, content={"detail": "Internal analysis error. Please try again."})


def _looks_like_url(text: str) -> bool:
    return bool(re.fullmatch(r"[\w.-]+\.[a-z]{2,}(/\S*)?", text, re.I))
