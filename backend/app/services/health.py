"""Health domain logic.

Deliberately independent of FastAPI: this module is plain Python so the same
check can be reused from a worker process or a CLI probe.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ComponentCheck:
    """Result of one dependency probe."""

    name: str
    status: str


@dataclass(frozen=True, slots=True)
class HealthReport:
    """Aggregate health of the service."""

    status: str
    service: str
    version: str
    checks: list[ComponentCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "service": self.service,
            "version": self.version,
            "checks": [{"name": c.name, "status": c.status} for c in self.checks],
        }


class HealthService:
    """Collects dependency probes.

    No probes are registered yet: this milestone has no database or queue
    connection to check. An empty check list is reported explicitly rather than
    implying that dependencies were verified.
    """

    def __init__(self, service_name: str, version: str) -> None:
        self._service_name = service_name
        self._version = version

    def report(self) -> HealthReport:
        checks: list[ComponentCheck] = []
        status = "ok" if all(c.status == "ok" for c in checks) else "degraded"
        return HealthReport(
            status=status,
            service=self._service_name,
            version=self._version,
            checks=checks,
        )
