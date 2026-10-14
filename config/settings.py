"""Runtime configuration models for the assessment application."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConnectionSettings:
    """Connection details supplied for one assessment session."""

    server: str
    domain: str
    username: str
    password: str
    use_ssl: bool = False
    port: int | None = None

    @property
    def effective_port(self) -> int:
        """Return the LDAP port implied by the transport mode."""
        return self.port or (636 if self.use_ssl else 389)