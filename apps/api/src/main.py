"""TrustedAgentHub FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import threading
from typing import Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .dependencies import clear_runtime_dependencies
from .errors import install_error_handlers
from .models.common import HealthResponse
from .routers.auth import router as auth_router
from .routers.feedback import router as feedback_router
from .routers.install import router as install_router
from .routers.packages import router as packages_router
from .routers.producer import router as producer_router
from .routers.review import router as review_router
from .routers.stats import router as stats_router
from .routers.admin import router as admin_router
from .routers.trust import (
    configure_registry_policy,
    router as trust_router,
    v1_router as trust_v1_router,
)
from .routers.trust_scores import router as trust_scores_router
from .settings import get_settings


_logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_application: FastAPI):
    """Start the scan recovery and maintenance workers; release resources on shutdown."""
    worker_stop = threading.Event()
    worker_threads: list[threading.Thread] = []
    try:
        from src.auth import install as install_auth
        install_auth()
        from src.routers.trust import (
            recover_persisted_scan_tasks,
            run_persisted_scan_recovery_loop,
            run_scan_maintenance,
            run_scan_maintenance_loop,
        )
        recover_persisted_scan_tasks()
        try:
            run_scan_maintenance()
        except Exception:
            _logger.exception("Initial scan maintenance failed")
        for target, name in (
            (run_persisted_scan_recovery_loop, "scan-recovery-loop"),
            (run_scan_maintenance_loop, "scan-maintenance-loop"),
        ):
            thread = threading.Thread(
                target=target,
                args=(worker_stop,),
                name=name,
                daemon=True,
            )
            thread.start()
            worker_threads.append(thread)
        yield
    finally:
        worker_stop.set()
        for thread in worker_threads:
            thread.join(timeout=2.0)
        clear_runtime_dependencies()


def create_app() -> FastAPI:
    """Create and configure the TrustedAgentHub API application."""
    settings = get_settings()
    # Validate server-owned trust configuration before accepting scans. Scan
    # workers reuse the immutable policy constructed here.
    try:
        configure_registry_policy(settings.approved_private_registries_json)
    except ValueError as exc:
        raise RuntimeError(
            "Invalid TAH_APPROVED_PRIVATE_REGISTRIES_JSON configuration: "
            f"{exc}"
        ) from exc
    application = FastAPI(
        title="Trusted Agent Hub API",
        version="0.1.0",
        description="Backend API for the TrustedAgentHub package registry.",
        lifespan=lifespan,
    )
    install_error_handlers(application)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allowed_origins),
        # Browser refresh tokens use an HttpOnly cookie. Wildcard origins
        # cannot be used with credentialed requests, so deployments that need
        # browser sessions must configure explicit CORS_ALLOWED_ORIGINS.
        allow_credentials="*" not in settings.cors_allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(auth_router)
    application.include_router(packages_router, prefix="/api/v0")
    application.include_router(install_router, prefix="/api/v0")
    application.include_router(feedback_router, prefix="/api/v0")
    application.include_router(trust_scores_router, prefix="/api/v0")
    application.include_router(stats_router, prefix="/api/v0")
    application.include_router(trust_router, prefix="/api/v0")
    application.include_router(trust_v1_router, prefix="/api/v1")
    application.include_router(producer_router)  # producer 路由自带 /api/v0 prefix
    application.include_router(review_router)
    application.include_router(admin_router)

    @application.get(
        "/api/v0/health", response_model=HealthResponse, tags=["health"]
    )
    def health() -> HealthResponse:
        return HealthResponse(
            service="Trusted Agent Hub API",
            version="0.1.0",
            status="ok",
        )

    return application


app = create_app()
