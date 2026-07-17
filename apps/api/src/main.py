"""TrustedAgentHub FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .dependencies import clear_runtime_dependencies
from .errors import install_error_handlers
from .models.common import HealthResponse
from .routers.feedback import router as feedback_router
from .routers.install import router as install_router
from .routers.packages import router as packages_router
from .routers.stats import router as stats_router
from .routers.trust import router as trust_router
from .routers.trust_scores import router as trust_scores_router


@asynccontextmanager
async def lifespan(_application: FastAPI):
    """Release process-wide database resources on application shutdown."""
    try:
        yield
    finally:
        clear_runtime_dependencies()


def create_app() -> FastAPI:
    """Create and configure the TrustedAgentHub API application."""
    application = FastAPI(
        title="Trusted Agent Hub API",
        version="0.1.0",
        description="Backend API for the TrustedAgentHub package registry.",
        lifespan=lifespan,
    )
    install_error_handlers(application)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(packages_router, prefix="/api/v0")
    application.include_router(install_router, prefix="/api/v0")
    application.include_router(feedback_router, prefix="/api/v0")
    application.include_router(trust_scores_router, prefix="/api/v0")
    application.include_router(stats_router, prefix="/api/v0")
    application.include_router(trust_router, prefix="/api/v0")

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
