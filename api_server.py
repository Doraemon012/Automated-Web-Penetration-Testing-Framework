"""FastAPI-based HTTP API for the Automated Web Penetration Testing Framework.

This service exposes the core scanning engine via REST endpoints so it can be
consumed by external clients such as browser extensions or other applications.
"""
from __future__ import annotations
import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Header, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, HttpUrl, root_validator

from main import prepared_scan_reporter
from db.mongo_repository import ScanRepository
from db.user_repository import UserRepository


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
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "webpentest")
MONGO_SCAN_COLLECTION = os.getenv("MONGO_SCANS_COLLECTION", "scans")
MONGO_USERS_COLLECTION = os.getenv("MONGO_USERS_COLLECTION", "users")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SCAN_REPOSITORY: Optional[ScanRepository] = None
USER_REPOSITORY: Optional[UserRepository] = None
if MONGO_URI and MONGO_DB_NAME:
    try:
        SCAN_REPOSITORY = ScanRepository(MONGO_URI, MONGO_DB_NAME, MONGO_SCAN_COLLECTION)
        logger.info(
            "MongoDB scan persistence enabled (db=%s, collection=%s)",
            MONGO_DB_NAME,
            MONGO_SCAN_COLLECTION,
        )
    except Exception as exc:  # pragma: no cover - startup failure path
        logger.error("Failed to initialize MongoDB scan repository: %s", exc)
    try:
        USER_REPOSITORY = UserRepository(MONGO_URI, MONGO_DB_NAME, MONGO_USERS_COLLECTION)
        logger.info(
            "MongoDB user repository enabled (db=%s, collection=%s)",
            MONGO_DB_NAME,
            MONGO_USERS_COLLECTION,
        )
    except Exception as exc:  # pragma: no cover - startup failure path
        logger.error("Failed to initialize MongoDB user repository: %s", exc)
else:
    logger.info("MongoDB persistence disabled (missing configuration)")


class InMemoryUserRepository:
    """Minimal dev-grade repository used when MongoDB is unavailable."""

    def __init__(self):
        self._lock = threading.Lock()
        self._users: Dict[str, Dict[str, Any]] = {}

    def create_user(self, email: str, hashed_password: str) -> Dict[str, Any]:
        normalized = email.lower()
        with self._lock:
            if normalized in self._users:
                raise ValueError("Email already exists")
            self._users[normalized] = {"email": normalized, "hashed_password": hashed_password}
        return {"email": normalized}

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        normalized = email.lower()
        with self._lock:
            user = self._users.get(normalized)
            return dict(user) if user else None

    def email_exists(self, email: str) -> bool:
        normalized = email.lower()
        with self._lock:
            return normalized in self._users


if USER_REPOSITORY is None:
    USER_REPOSITORY = InMemoryUserRepository()
    logger.warning("Using in-memory user repository; credentials reset on restart")
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


class AuthRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class AuthLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


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

    def __init__(self, max_workers: int = 2, repository: Optional[ScanRepository] = None):
        self._jobs: Dict[str, ScanJob] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._manager_lock = threading.Lock()
        self._repository = repository

    def create_job(self, target_url: str, mode: str, use_js: bool, auth_config: Optional[Dict[str, Any]]) -> ScanJob:
        job = ScanJob(target_url=target_url, mode=mode, use_js=use_js, auth_config=auth_config)
        with self._manager_lock:
            self._jobs[job.id] = job
        self._executor.submit(self._run_job, job)
        logger.info("Enqueued scan job %s for %s", job.id, target_url)
        self._persist_job(job)
        return job

    def get_job(self, job_id: str) -> ScanJob:
        with self._manager_lock:
            if job_id not in self._jobs:
                raise KeyError(job_id)
            return self._jobs[job_id]

    def get_snapshot(self, job_id: str) -> Dict[str, Any]:
        job = self._get_job_if_present(job_id)
        if job:
            return job.snapshot()

        snapshot = self._load_snapshot_from_repository(job_id)
        if snapshot:
            return snapshot
        raise KeyError(job_id)

    def get_result_document(self, job_id: str) -> Dict[str, Any]:
        job = self._get_job_if_present(job_id)
        if job and job.result:
            return self._hydrate_result_payload(job.snapshot_result())

        if self._repository:
            document = self._repository.get_scan(job_id)
            if document and document.get("result_full"):
                return self._hydrate_result_payload(document["result_full"])

        raise KeyError(job_id)

    def list_snapshots(self, limit: int = 20) -> List[Dict[str, Any]]:
        if self._repository:
            documents = self._repository.list_scans(limit)
            return [self._document_to_snapshot(doc) for doc in documents]

        with self._manager_lock:
            jobs = sorted(self._jobs.values(), key=lambda job: job.created_at, reverse=True)
            return [job.snapshot() for job in jobs[:limit]]

    def _run_job(self, job: ScanJob) -> None:
        logger.info("Starting scan job %s", job.id)
        job.update(status="running", progress=5, message="Normalizing target URL", started_at=datetime.utcnow())
        self._persist_job(job)

        try:
            normalized_target = str(job.target_url)
            job.update(progress=10, message="Launching scanner")
            self._persist_job(job)

            with prepared_scan_reporter(
                normalized_target,
                auth_config=job.auth_config,
                use_js=job.use_js,
                mode=job.mode,
            ) as reporter:
                job.update(progress=70, message="Enriching findings")
                self._persist_job(job)

                findings = list(reporter.iter_findings())
                sanitized = _sanitize_findings(findings)

                job.update(progress=85, message="Generating reports")
                self._persist_job(job)
                result_payload = _build_result_payload(job, sanitized)

                reporter.save_json(result_payload["report_files"]["json"], findings=sanitized)
                reporter.save_markdown(result_payload["report_files"]["markdown"], findings=sanitized)

            job.update(
                status="completed",
                progress=100,
                message="Scan completed",
                completed_at=datetime.utcnow(),
                result=result_payload,
            )
            logger.info("Scan job %s completed", job.id)
            self._persist_job(job)
            self._release_job_memory(job)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Scan job %s failed", job.id)
            job.update(status="failed", progress=100, message="Scan failed", error=str(exc))
            self._persist_job(job)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)

    def job_stats(self) -> Dict[str, int]:
        with self._manager_lock:
            total = len(self._jobs)
            running = sum(1 for job in self._jobs.values() if job.status == "running")
            queued = sum(1 for job in self._jobs.values() if job.status == "queued")
        return {"total": total, "running": running, "queued": queued}

    def _persist_job(self, job: ScanJob) -> None:
        if not self._repository:
            return

        snapshot = job.snapshot()
        document: Dict[str, Any] = dict(snapshot)
        document["auth_config"] = job.auth_config
        if job.result:
            try:
                document["result_full"] = job.snapshot_result()
            except ValueError:
                document["result_full"] = None
        else:
            document["result_full"] = None
        self._repository.upsert(document)

    def _release_job_memory(self, job: ScanJob) -> None:
        """Drop large fields from the in-memory job result once persisted."""
        with job._lock:
            if not job.result:
                return
            findings = job.result.get("findings")
            if isinstance(findings, list):
                job.result["findings"] = None

    def _hydrate_result_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        hydrated = dict(payload)
        if hydrated.get("findings"):
            return hydrated
        report_files = hydrated.get("report_files") or {}
        report_path = report_files.get("json")
        hydrated["findings"] = _load_findings_from_file(report_path)
        return hydrated

    def _get_job_if_present(self, job_id: str) -> Optional[ScanJob]:
        with self._manager_lock:
            return self._jobs.get(job_id)

    def _load_snapshot_from_repository(self, job_id: str) -> Optional[Dict[str, Any]]:
        if not self._repository:
            return None
        document = self._repository.get_scan(job_id)
        if not document:
            return None
        return self._document_to_snapshot(document)

    @staticmethod
    def _document_to_snapshot(document: Dict[str, Any]) -> Dict[str, Any]:
        keys = [
            "scan_id",
            "status",
            "progress",
            "message",
            "created_at",
            "updated_at",
            "started_at",
            "completed_at",
            "target_url",
            "mode",
            "use_js",
            "result",
            "error",
        ]
        snapshot = {key: document.get(key) for key in keys}
        if "result" not in snapshot:
            snapshot["result"] = None
        return snapshot


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


def _hash_password(password: str) -> str:
    return password_context.hash(password)


def _verify_password(password: str, hashed: str) -> bool:
    try:
        return password_context.verify(password, hashed)
    except ValueError:
        return False


def _create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def _decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:  # pragma: no cover - crypto edge cases
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token") from exc

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    return subject


def _require_user_repository() -> UserRepository:
    if not USER_REPOSITORY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User repository not configured",
        )
    return USER_REPOSITORY


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


def _load_findings_from_file(report_path: Optional[str]) -> List[Dict[str, Any]]:
    if not report_path:
        return []
    try:
        path = Path(report_path).resolve()
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            findings = data.get("findings")
            if isinstance(findings, list):
                return findings
            return []
        if isinstance(data, list):
            return data
    except FileNotFoundError:
        logger.warning("Report file missing when hydrating findings: %s", report_path)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse findings file %s: %s", report_path, exc)
    except Exception as exc:  # pragma: no cover - unexpected filesystem errors
        logger.error("Unexpected error loading findings from %s: %s", report_path, exc)
    return []

def _require_authorized_client(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> None:
    if API_AUTH_TOKEN and x_api_key == API_AUTH_TOKEN:
        return

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if token:
            _decode_access_token(token)
            return

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing credentials")


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
    allow_origin_regex=None if allow_all else r"chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_manager = ScanManager(max_workers=MAX_WORKERS, repository=SCAN_REPOSITORY)


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


@app.post("/api/auth/register")
async def register_user(payload: AuthRegisterRequest) -> Dict[str, str]:
    repo = _require_user_repository()
    if repo.email_exists(payload.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    hashed_password = _hash_password(payload.password)
    repo.create_user(payload.email, hashed_password)
    return {"message": "Registration successful"}


@app.post("/api/auth/login", response_model=TokenResponse)
async def login_user(payload: AuthLoginRequest) -> TokenResponse:
    repo = _require_user_repository()
    user = repo.get_user_by_email(payload.email)
    if not user or not _verify_password(payload.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = _create_access_token(user["email"])
    return TokenResponse(access_token=token)


@app.get("/api/scans", response_model=List[ScanStatusResponse])
async def list_scans(limit: int = Query(20, ge=1, le=100), _: None = Depends(_require_authorized_client)) -> List[ScanStatusResponse]:
    snapshots = scan_manager.list_snapshots(limit)
    responses: List[ScanStatusResponse] = []
    for snapshot in snapshots:
        snapshot_copy = dict(snapshot)
        raw_result = snapshot_copy.pop("result", None)
        responses.append(
            ScanStatusResponse(
                **snapshot_copy,
                result=_build_summary(raw_result),
            )
        )
    return responses


@app.post("/api/scan", response_model=ScanStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(request: ScanRequest, _: None = Depends(_require_authorized_client)) -> ScanStatusResponse:
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
async def get_status(scan_id: str, _: None = Depends(_require_authorized_client)) -> ScanStatusResponse:
    try:
        snapshot = scan_manager.get_snapshot(scan_id)
    except KeyError as exc:  # pragma: no cover - simple 404 path
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc

    raw_result = snapshot.pop("result", None)
    return ScanStatusResponse(
        **snapshot,
        result=_build_summary(raw_result),
    )


@app.get("/api/results/{scan_id}", response_model=ScanResultResponse)
async def get_results(scan_id: str, _: None = Depends(_require_authorized_client)) -> ScanResultResponse:
    try:
        snapshot = scan_manager.get_snapshot(scan_id)
    except KeyError as exc:  # pragma: no cover - simple 404 path
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc

    if snapshot["status"] == "failed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=snapshot.get("error") or "Scan failed")
    if snapshot["status"] != "completed":
        raise HTTPException(status_code=status.HTTP_202_ACCEPTED, detail="Scan still in progress")

    try:
        result = scan_manager.get_result_document(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result not found") from exc

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
async def download_report(scan_id: str, report_type: str, _: None = Depends(_require_authorized_client)) -> FileResponse:
    if report_type not in {"json", "markdown"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report type")

    try:
        result = scan_manager.get_result_document(scan_id)
    except KeyError as exc:  # pragma: no cover
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc

    file_path = Path(result["report_files"][report_type]).resolve()
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
