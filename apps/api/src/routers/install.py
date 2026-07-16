"""Strict Install Manifest v1.0 HTTP route."""

from typing import Annotated

from fastapi import APIRouter, Query

from src.dependencies import RepositoryDependency
from src.models.common import ErrorEnvelope
from src.models.install import InstallManifest, InstallManifestQuery
from src.services.install import InstallManifestService


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
    name: str,
    query: Annotated[InstallManifestQuery, Query()],
    repository: RepositoryDependency,
) -> InstallManifest:
    return InstallManifestService(repository).get_manifest(
        name=name,
        client=query.client,
        version=query.version,
    )
