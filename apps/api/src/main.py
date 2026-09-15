"""TrustedAgentHub FastAPI application factory."""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, InvalidStateError
from contextlib import asynccontextmanager
import logging
import random
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
    _cleanup_expired_scans,
    _has_expired_scan_cleanup_backlog,
    router as trust_router,
)
from .routers.trust import v1_router as trust_v1_router
from .routers.trust_scores import router as trust_scores_router
from .settings import get_settings


_logger = logging.getLogger(__name__)

# 清理节奏：间隔来自 settings.scan_cleanup_interval_seconds（默认 600s，有界 60–3600s）。
_SCAN_CLEANUP_INITIAL_JITTER_SECONDS = 60.0
_SCAN_CLEANUP_BACKLOG_INTERVAL_SECONDS = 60.0
_SCAN_CLEANUP_SHUTDOWN_TIMEOUT_SECONDS = 30.0


async def _wait_for_scan_cleanup_stop(
    stop_event: asyncio.Event,
    timeout_seconds: float,
) -> bool:
    """Wait for shutdown, returning True when the stop signal was received."""
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return False
    return True


async def _scan_cleanup_loop(
    stop_event: asyncio.Event,
    interval_seconds: int,
) -> None:
    """Periodically clean this worker's in-memory scan records."""
    initial_delay = random.uniform(0.0, _SCAN_CLEANUP_INITIAL_JITTER_SECONDS)
    if await _wait_for_scan_cleanup_stop(stop_event, initial_delay):
        return

    while not stop_event.is_set():
        try:
            await _run_scan_cleanup_pass()
        except asyncio.CancelledError:
            raise
        except Exception:
            # A failed pass must not terminate the worker that performs later
            # cleanup rounds.
            _logger.exception("Periodic scan cleanup failed")

        if stop_event.is_set():
            return

        next_interval = float(interval_seconds)
        if _has_expired_scan_cleanup_backlog():
            next_interval = _SCAN_CLEANUP_BACKLOG_INTERVAL_SECONDS
        if await _wait_for_scan_cleanup_stop(stop_event, next_interval):
            return


def _start_scan_cleanup_thread() -> Future[int]:
    future: Future[int] = Future()

    def run() -> None:
        try:
            result = _cleanup_expired_scans()
        except BaseException as exc:
            if not future.cancelled():
                try:
                    future.set_exception(exc)
                except InvalidStateError:
                    pass
        else:
            if not future.cancelled():
                try:
                    future.set_result(result)
                except InvalidStateError:
                    pass

    threading.Thread(
        target=run,
        name="scan-cleanup-io",
        daemon=True,
    ).start()
    return future


async def _run_scan_cleanup_pass() -> int:
    """Run one cleanup pass without attaching I/O to asyncio's executor."""
    return await asyncio.wrap_future(_start_scan_cleanup_thread())


async def _stop_scan_cleanup_task(
    stop_event: asyncio.Event,
    cleanup_task: asyncio.Task[None] | None,
) -> None:
    """Stop the cleanup worker without making application shutdown unbounded."""
    stop_event.set()
    if cleanup_task is None:
        return

    try:
        # Directory deletion runs in a killable worker process with its own
        # shorter deadline.  The shield lets that bounded pass report its
        # result without turning shutdown cancellation into a new error.
        await asyncio.wait_for(
            asyncio.shield(cleanup_task),
            timeout=_SCAN_CLEANUP_SHUTDOWN_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        _logger.warning(
            "Timed out waiting for scan cleanup during shutdown after %.1f seconds",
            _SCAN_CLEANUP_SHUTDOWN_TIMEOUT_SECONDS,
        )
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        except Exception:
            _logger.exception("Scan cleanup failed while being cancelled")
    except asyncio.CancelledError:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        except Exception:
            _logger.exception("Scan cleanup failed while shutting down")
        raise
    except Exception:
        _logger.exception("Scan cleanup task exited with an error")


@asynccontextmanager
async def lifespan(_application: FastAPI):
    """Start scan workers and the periodic cleanup task; release resources on shutdown."""
    worker_stop = threading.Event()
    worker_threads: list[threading.Thread] = []
    stop_event = asyncio.Event()
    cleanup_task: asyncio.Task[None] | None = None
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
        cleanup_task = asyncio.create_task(
            _scan_cleanup_loop(
                stop_event,
                get_settings().scan_cleanup_interval_seconds,
            ),
            name="scan-cleanup",
        )
        yield
    finally:
        try:
            await _stop_scan_cleanup_task(stop_event, cleanup_task)
        finally:
            worker_stop.set()
            for thread in worker_threads:
                thread.join(timeout=2.0)
            clear_runtime_dependencies()


def create_app() -> FastAPI:
    """Create and configure the TrustedAgentHub API application."""
    settings = get_settings()
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
