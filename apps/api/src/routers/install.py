"""Strict Install Manifest v1.0 HTTP route — plus artifact download."""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse

from src.dependencies import RepositoryDependency
from src.models.common import ErrorEnvelope
from src.models.install import InstallManifest, InstallManifestQuery
from src.services.install import InstallManifestService
from src.services.artifacts import ARTIFACTS_ROOT


router = APIRouter(tags=["install"])


@router.get(
    "/packages/{name}/install-manifest",
    response_model=InstallManifest,
    responses={
        404: {"model": ErrorEnvelope},
        409: {"model": ErrorEnvelope},
    },
)
def get_install_manifest(
    request: Request,
    name: str,
    query: Annotated[InstallManifestQuery, Query()],
    repository: RepositoryDependency,
) -> InstallManifest:
    return InstallManifestService(
        repository,
        public_base_url=str(request.base_url),
    ).get_manifest(
        name=name,
        client=query.client,
        version=query.version,
    )


@router.get("/artifacts/{filename}")
def download_artifact(filename: str) -> FileResponse:
    """Serve a previously-built install artifact (ZIP)."""
    safe_name = Path(filename).name  # prevent path traversal
    file_path = ARTIFACTS_ROOT / safe_name
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(
        path=str(file_path),
        media_type="application/zip",
        filename=safe_name,
    )
