"""FastAPI-based HTTP API for the Automated Web Penetration Testing Framework.

This service exposes the core scanning engine via REST endpoints so it can be
consumed by external clients such as browser extensions or other applications.
"""
from __future__ import annotations
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, HttpUrl, root_validator

from main import run_complete_scan
from reports.cvss_compute import enhance_finding_with_cvss, deduplicate_findings
from reports.reporter import Reporter
from reports.risk import enrich_findings


def _resolve_log_level() -> int | str:
    level = os.getenv("API_LOG_LEVEL", "INFO")
    if isinstance(level, str):
        level = level.strip()
        if level.isdigit():
            return int(level)
        return level.upper()
    return level


logger = logging.getLogger("webpentest.api")
logging.basicConfig(level=_resolve_log_level())

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_AUTH_TOKEN = os.getenv("WEBPENTEST_API_KEY")
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("API_ALLOWED_ORIGINS", "*").split(",")]
MAX_WORKERS = int(os.getenv("API_MAX_WORKERS", "2"))
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports")).resolve()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SERVICE_STARTED_AT = datetime.utcnow()

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AuthConfig(BaseModel):
    """Authentication configuration for the scan request."""

    type: str = Field(..., description="Authentication type: form|token|basic")
    username: Optional[str] = Field(None, description="Username for form/basic auth")
    password: Optional[str] = Field(None, description="Password for form/basic auth")
    login_url: Optional[str] = Field(None, description="Login URL for form auth")
    token: Optional[str] = Field(None, description="Token value for token auth")
    username_field: str = Field("username", description="Username field name for forms")
    password_field: str = Field("password", description="Password field name for forms")
    header_name: str = Field("Authorization", description="Header name for token auth")
    token_prefix: str = Field("Bearer", description="Token prefix for token auth")

    @root_validator
    def validate_required_fields(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        auth_type = values.get("type")
        if auth_type not in {"form", "token", "basic"}:
            raise ValueError("Unsupported auth type. Choose from form, token, basic.")

        if auth_type == "form":
            if not all(values.get(field) for field in ("login_url", "username", "password")):
                raise ValueError("Form authentication requires login_url, username, and password.")
        elif auth_type == "token":
            if not values.get("token"):
                raise ValueError("Token authentication requires a token value.")
        elif auth_type == "basic":
            if not all(values.get(field) for field in ("username", "password")):
                raise ValueError("Basic authentication requires username and password.")
        return values

    def to_cli_config(self) -> Dict[str, Any]:
        """Convert the Pydantic model into the dict structure the scanner expects."""
        base = {"type": self.type}
        if self.type == "form":
            base.update(
                {
                    "login_url": self.login_url,
                    "username": self.username,
                    "password": self.password,
                    "username_field": self.username_field,
                    "password_field": self.password_field,
                }
            )
        elif self.type == "token":
            base.update(
                {
                    "token": self.token,
                    "header_name": self.header_name or "Authorization",
                    "token_prefix": self.token_prefix or "Bearer",
                }
            )
        elif self.type == "basic":
            base.update(
                {
                    "username": self.username,
                    "password": self.password,
                }
            )
        return base


class ScanRequest(BaseModel):
    """Incoming scan request payload."""

    url: HttpUrl = Field(..., description="Target URL to scan")
    mode: str = Field("standard", description="Scan mode: ultra-safe|safe|standard|aggressive")
    use_js: bool = Field(False, description="Enable JavaScript crawler if available")
    auth: Optional[AuthConfig] = Field(None, description="Authentication configuration")

    @root_validator
    def validate_mode(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        mode = values.get("mode", "standard")
        allowed = {"ultra-safe", "safe", "standard", "aggressive"}
        if mode not in allowed:
            raise ValueError(f"Invalid mode '{mode}'. Allowed values: {', '.join(sorted(allowed))}.")
        return values


class ScanResultSummary(BaseModel):
    """Short result summary included in status responses."""

    target_url: str
    mode: str
    use_js: bool
    started_at: datetime
    completed_at: datetime
    total_findings: int
    severity_counts: Dict[str, int]
    report_files: Dict[str, str]


class ScanStatusResponse(BaseModel):
    """Status response for scan initiation and polling."""

    scan_id: str
    status: str
    progress: int
    message: str
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    target_url: str
    mode: str
    use_js: bool
    result: Optional[ScanResultSummary] = None
    error: Optional[str] = None


class ScanResultResponse(BaseModel):
    """Full scan result response."""

    scan_id: str
    target_url: str
    mode: str
    use_js: bool
    started_at: datetime
    completed_at: datetime
    total_findings: int
    severity_counts: Dict[str, int]
    report_files: Dict[str, str]
    findings: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Scan job management
# ---------------------------------------------------------------------------

class ScanJob:
    """Represents an individual scan job and its mutable state."""

    def __init__(self, target_url: str, mode: str, use_js: bool, auth_config: Optional[Dict[str, Any]]):
        self.id = uuid4().hex
        self.target_url = target_url
        self.mode = mode
        self.use_js = use_js
        self.auth_config = auth_config

        now = datetime.utcnow()
        self.created_at: datetime = now
        self.updated_at: datetime = now
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

        self.status: str = "queued"
        self.progress: int = 0
        self.message: str = "Scan queued"
        self.error: Optional[str] = None
        self.result: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()

    def update(self, **kwargs: Any) -> None:
        """Thread-safe state update helper."""
        with self._lock:
            for key, value in kwargs.items():
                setattr(self, key, value)
            self.updated_at = datetime.utcnow()

    def snapshot(self) -> Dict[str, Any]:
        """Return a serialisable snapshot of the job state."""
        with self._lock:
            base: Dict[str, Any] = {
                "scan_id": self.id,
                "status": self.status,
                "progress": self.progress,
                "message": self.message,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "target_url": self.target_url,
                "mode": self.mode,
                "use_js": self.use_js,
                "result": None,
                "error": self.error,
            }
            if self.result:
                summary = {k: v for k, v in self.result.items() if k != "findings"}
                base["result"] = summary
            return base

    def snapshot_result(self) -> Dict[str, Any]:
        with self._lock:
            if not self.result:
                raise ValueError("Result not available")
            result_copy = dict(self.result)
            result_copy["scan_id"] = self.id
            return result_copy


class ScanManager:
    """Manages scan job lifecycle and execution."""

    def __init__(self, max_workers: int = 2):
        self._jobs: Dict[str, ScanJob] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._manager_lock = threading.Lock()

    def create_job(self, target_url: str, mode: str, use_js: bool, auth_config: Optional[Dict[str, Any]]) -> ScanJob:
        job = ScanJob(target_url=target_url, mode=mode, use_js=use_js, auth_config=auth_config)
        with self._manager_lock:
            self._jobs[job.id] = job
        self._executor.submit(self._run_job, job)
        logger.info("Enqueued scan job %s for %s", job.id, target_url)
        return job

    def get_job(self, job_id: str) -> ScanJob:
        with self._manager_lock:
            if job_id not in self._jobs:
                raise KeyError(job_id)
            return self._jobs[job_id]

    def _run_job(self, job: ScanJob) -> None:
        logger.info("Starting scan job %s", job.id)
        job.update(status="running", progress=5, message="Normalizing target URL", started_at=datetime.utcnow())

        try:
            normalized_target = str(job.target_url)
            job.update(progress=10, message="Launching scanner")

            findings = run_complete_scan(
                normalized_target,
                auth_config=job.auth_config,
                use_js=job.use_js,
                mode=job.mode,
            )

            job.update(progress=70, message="Enriching findings")
            enriched = [enhance_finding_with_cvss(f) for f in findings]
            enriched = deduplicate_findings(enriched)
            enriched = enrich_findings(enriched)
            sanitized = _sanitize_findings(enriched)

            job.update(progress=85, message="Generating reports")
            result_payload = _build_result_payload(job, sanitized)

            reporter = Reporter()
            reporter.findings = sanitized
            reporter.save_json(result_payload["report_files"]["json"])  # type: ignore[arg-type]
            reporter.save_markdown(result_payload["report_files"]["markdown"])  # type: ignore[arg-type]

            job.update(
                status="completed",
                progress=100,
                message="Scan completed",
                completed_at=datetime.utcnow(),
                result=result_payload,
            )
            logger.info("Scan job %s completed", job.id)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Scan job %s failed", job.id)
            job.update(status="failed", progress=100, message="Scan failed", error=str(exc))

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)

    def job_stats(self) -> Dict[str, int]:
        with self._manager_lock:
            total = len(self._jobs)
            running = sum(1 for job in self._jobs.values() if job.status == "running")
            queued = sum(1 for job in self._jobs.values() if job.status == "queued")
        return {"total": total, "running": running, "queued": queued}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _sanitize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sanitized: List[Dict[str, Any]] = []
    for finding in findings:
        data = dict(finding)
        data.setdefault("url", "")
        data.setdefault("vulnerability", "Unknown Finding")
        data.setdefault("severity", "Unknown")
        data["payload"] = finding.get("payload") or ""
        data.setdefault("description", "")
        data.setdefault("recommendation", "")
        data.setdefault("evidence", "")
        sanitized.append(data)
    return sanitized


def _build_result_payload(job: ScanJob, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_counts: Dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{timestamp}_{job.id[:8]}"
    json_path = REPORTS_DIR / f"{base_name}.json"
    md_path = REPORTS_DIR / f"{base_name}.md"

    return {
        "target_url": job.target_url,
        "mode": job.mode,
        "use_js": job.use_js,
        "started_at": job.started_at or datetime.utcnow(),
        "completed_at": datetime.utcnow(),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "report_files": {
            "json": str(json_path),
            "markdown": str(md_path),
        },
        "findings": findings,
    }


def _require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if API_AUTH_TOKEN and x_api_key != API_AUTH_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")


def _relative_report_path(path_str: str) -> str:
    path = Path(path_str)
    try:
        return os.path.relpath(path, Path.cwd())
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# FastAPI application setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Automated Web Pentest API", version="1.0.0")

allow_all = len(ALLOWED_ORIGINS) == 1 and ALLOWED_ORIGINS[0] == "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allow_all else ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_manager = ScanManager(max_workers=MAX_WORKERS)


@app.on_event("shutdown")
async def shutdown_event() -> None:  # pragma: no cover - FastAPI infrastructure
    scan_manager.shutdown()


@app.get("/api/status/health")
async def health_check() -> Dict[str, Any]:
    stats = scan_manager.job_stats()
    return {
        "status": "ok",
        "version": app.version,
        "started_at": SERVICE_STARTED_AT,
        "uptime_seconds": int((datetime.utcnow() - SERVICE_STARTED_AT).total_seconds()),
        "job_counts": stats,
        "max_workers": MAX_WORKERS,
    }


@app.post("/api/scan", response_model=ScanStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(request: ScanRequest, _: None = Depends(_require_api_key)) -> ScanStatusResponse:
    auth_config = request.auth.to_cli_config() if request.auth else None
    job = scan_manager.create_job(
        target_url=str(request.url),
        mode=request.mode,
        use_js=request.use_js,
        auth_config=auth_config,
    )
    snapshot = job.snapshot()
    raw_result = snapshot.pop("result", None)
    return ScanStatusResponse(
        **snapshot,
        result=_build_summary(raw_result),
    )


@app.get("/api/status/{scan_id}", response_model=ScanStatusResponse)
async def get_status(scan_id: str, _: None = Depends(_require_api_key)) -> ScanStatusResponse:
    try:
        job = scan_manager.get_job(scan_id)
    except KeyError as exc:  # pragma: no cover - simple 404 path
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc

    snapshot = job.snapshot()
    raw_result = snapshot.pop("result", None)
    return ScanStatusResponse(
        **snapshot,
        result=_build_summary(raw_result),
    )


@app.get("/api/results/{scan_id}", response_model=ScanResultResponse)
async def get_results(scan_id: str, _: None = Depends(_require_api_key)) -> ScanResultResponse:
    try:
        job = scan_manager.get_job(scan_id)
    except KeyError as exc:  # pragma: no cover - simple 404 path
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc

    if job.status == "failed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=job.error or "Scan failed")
    if job.status != "completed" or not job.result:
        raise HTTPException(status_code=status.HTTP_202_ACCEPTED, detail="Scan still in progress")

    result = job.snapshot_result()

    report_files = {
        key: _relative_report_path(value) for key, value in result["report_files"].items()
    }

    return ScanResultResponse(
        scan_id=scan_id,
        target_url=result["target_url"],
        mode=result["mode"],
        use_js=result["use_js"],
        started_at=result["started_at"],
        completed_at=result["completed_at"],
        total_findings=result["total_findings"],
        severity_counts=result["severity_counts"],
        report_files=report_files,
        findings=result["findings"],
    )


@app.get("/api/reports/{scan_id}/{report_type}")
async def download_report(scan_id: str, report_type: str, _: None = Depends(_require_api_key)) -> FileResponse:
    if report_type not in {"json", "markdown"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report type")

    try:
        job = scan_manager.get_job(scan_id)
    except KeyError as exc:  # pragma: no cover
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc

    if job.status != "completed" or not job.result:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Report not ready")

    file_path = Path(job.result["report_files"][report_type]).resolve()
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file missing")

    return FileResponse(path=file_path, filename=file_path.name)


def _build_summary(raw_summary: Optional[Dict[str, Any]]) -> Optional[ScanResultSummary]:
    if not raw_summary:
        return None

    report_files = {key: _relative_report_path(value) for key, value in raw_summary["report_files"].items()}

    return ScanResultSummary(
        target_url=raw_summary["target_url"],
        mode=raw_summary["mode"],
        use_js=raw_summary["use_js"],
        started_at=raw_summary["started_at"],
        completed_at=raw_summary["completed_at"],
        total_findings=raw_summary["total_findings"],
        severity_counts=raw_summary["severity_counts"],
        report_files=report_files,
    )


# Entrypoint for `uvicorn api_server:app`
if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("api_server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
