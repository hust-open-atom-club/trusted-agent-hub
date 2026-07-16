"""TrustedAgentHub FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .errors import install_error_handlers
from .models.common import HealthResponse
from .routers.install import router as install_router
from .routers.packages import router as packages_router
from .routers.stats import router as stats_router
from .routers.trust import router as trust_router
from .routers.trust_scores import router as trust_scores_router


def create_app() -> FastAPI:
    """Create and configure the TrustedAgentHub API application."""
    application = FastAPI(
        title="Trusted Agent Hub API",
        version="0.1.0",
        description="Backend API for the TrustedAgentHub package registry.",
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
