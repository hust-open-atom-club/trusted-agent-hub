"""Transport-neutral errors raised by Consumer API services."""


class ServiceNotFoundError(Exception):
    """Base for canonical service-domain not-found failures."""

    code: str

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, object] = {}


class PackageNotFoundError(ServiceNotFoundError):
    code = "package_not_found"

    def __init__(self, name: str) -> None:
        super().__init__(f"Package '{name}' was not found.")


class VersionNotFoundError(ServiceNotFoundError):
    code = "version_not_found"

    def __init__(self, reference: str) -> None:
        super().__init__(f"Version '{reference}' was not found.")


class TrustScoreNotFoundError(ServiceNotFoundError):
    code = "trust_score_not_found"

    def __init__(self, version_id: str) -> None:
        super().__init__(
            f"Trust score for version '{version_id}' was not found."
        )
