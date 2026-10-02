"""Application configuration.

All environment-specific behaviour is driven from :class:`Settings`, which is
loaded once per process and cached. Nothing in this module reads environment
variables directly, and no secret has a usable default: production startup
fails loudly rather than silently running with weak configuration.

See ``docs/deployment.md`` for the Render environment variable matrix.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.constants import APP_NAME, APP_SLUG, APP_VERSION

AppEnvironment = Literal["development", "test", "staging", "production"]
StorageBackend = Literal["s3", "memory"]
RateLimitBackend = Literal["memory", "redis"]

#: Values that are acceptable placeholders but are never allowed in production.
#: Configuration is validated against this list so that a copied ``.env.example``
#: cannot reach a production deployment.
INSECURE_PLACEHOLDER_SECRETS = frozenset(
    {
        "replace-me-with-at-least-32-random-characters",
        "replace-me-with-a-different-32-plus-random-characters",
        "changeme",
        "secret",
        "please-change-me",
    }
)

MIN_SECRET_KEY_LENGTH = 32

#: File types accepted as work evidence. Validated again server-side against the
#: actual uploaded bytes' MIME type and magic-number signature.
ALLOWED_UPLOAD_MIME_TYPES: frozenset[str] = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/webp",
        "application/pdf",
    }
)

ALLOWED_UPLOAD_EXTENSIONS: frozenset[str] = frozenset({".jpg", ".jpeg", ".png", ".webp", ".pdf"})


def _split_csv(value: Any) -> Any:
    """Normalise a comma-separated environment string into a list.

    Used for list-valued settings so operators can write
    ``CORS_ALLOWED_ORIGINS=https://a.example,https://b.example`` instead of
    having to embed JSON in an environment variable.
    """
    if value is None or isinstance(value, (list, tuple, set)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            # Tolerate JSON arrays too; pydantic-settings handles the decode.
            return value
        return [item.strip() for item in text.split(",") if item.strip()]
    return value


def _normalise_origin(value: str) -> str:
    origin = value.strip().rstrip("/")
    return origin.lower()


class Settings(BaseSettings):
    """Typed, validated application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    # ----------------------------------------------------------------- app --
    app_name: str = APP_NAME
    app_slug: str = APP_SLUG
    app_version: str = APP_VERSION
    app_env: AppEnvironment = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_json: bool = True
    api_v1_prefix: str = "/api/v1"

    #: Extra hostnames accepted in the ``Host`` header. Guards against
    #: Host-header poisoning of generated links and cache poisoning.
    allowed_hosts: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # ------------------------------------------------------------ database --
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/fundipulse"
    database_pool_size: int = Field(default=5, ge=1, le=100)
    database_max_overflow: int = Field(default=10, ge=0, le=200)
    database_pool_recycle_seconds: int = Field(default=1800, ge=30, le=86400)
    database_echo: bool = False
    #: Reject connections that do not opt into TLS. Render's managed Postgres
    #: connects over the private network and does not currently require TLS.
    database_require_ssl: bool = False

    # ------------------------------------------------------------- secrets --
    secret_key: SecretStr = SecretStr("")
    jwt_secret: SecretStr = SecretStr("")
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    jwt_issuer: str = "fundipulse"
    jwt_audience: str = "fundipulse-api"
    access_token_expire_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=30, ge=1, le=365)
    refresh_token_absolute_lifetime_days: int = Field(default=90, ge=1, le=730)

    # ------------------------------------------------------------ password --
    password_min_length: int = Field(default=12, ge=8, le=128)
    password_max_length: int = Field(default=128, ge=16, le=1024)
    #: Break-glass switch for the password policy. Must never be off in
    #: production; see :meth:`_validate_production_posture`.
    password_policy_enforced: bool = True
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost: int = Field(default=65536, ge=8192, le=1048576)
    argon2_parallelism: int = Field(default=4, ge=1, le=16)

    max_failed_login_attempts: int = Field(default=10, ge=1, le=100)
    account_lockout_minutes: int = Field(default=15, ge=1, le=1440)
    password_reset_token_expire_minutes: int = Field(default=30, ge=5, le=1440)
    email_verification_token_expire_hours: int = Field(default=48, ge=1, le=720)

    # ---------------------------------------------------------------- cors --
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    cors_allow_credentials: bool = False

    # ---------------------------------------------------------------- docs --
    enable_docs: bool = True

    # --------------------------------------------------------- rate limits --
    rate_limit_enabled: bool = True
    rate_limit_backend: RateLimitBackend = "memory"
    redis_url: SecretStr = SecretStr("")
    rate_limit_login_per_5_min: int = Field(default=10, ge=1)
    rate_limit_register_per_hour: int = Field(default=5, ge=1)
    rate_limit_password_reset_per_hour: int = Field(default=5, ge=1)
    rate_limit_password_change_per_hour: int = Field(default=10, ge=1)
    rate_limit_verification_request_per_day: int = Field(default=20, ge=1)
    rate_limit_file_upload_per_hour: int = Field(default=40, ge=1)
    rate_limit_job_apply_per_day: int = Field(default=25, ge=1)
    rate_limit_search_per_minute: int = Field(default=120, ge=1)
    rate_limit_default_per_minute: int = Field(default=300, ge=1)

    # ------------------------------------------------------------- storage --
    storage_backend: StorageBackend = "memory"
    storage_bucket: str = ""
    storage_endpoint: str | None = None
    storage_access_key: SecretStr = SecretStr("")
    storage_secret_key: SecretStr = SecretStr("")
    storage_region: str = "af-south-1"
    storage_use_path_style: bool = False
    max_upload_size_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    signed_url_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    malware_scanning_enabled: bool = False

    # ------------------------------------------------------ observability --
    sentry_dsn: SecretStr = SecretStr("")
    sentry_traces_sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)

    # ----------------------------------------------------------- retention --
    inactive_account_purge_days: int = Field(default=30, ge=1, le=3650)

    # ================================================================ #
    # Validators                                                       #
    # ================================================================ #

    @field_validator(
        "allowed_hosts",
        "cors_allowed_origins",
        mode="before",
    )
    @classmethod
    def _validate_csv_lists(cls, value: Any) -> Any:
        return _split_csv(value)

    @field_validator("cors_allowed_origins")
    @classmethod
    def _validate_origins(cls, value: list[str]) -> list[str]:
        normalised = [_normalise_origin(origin) for origin in value]
        for origin in normalised:
            if origin == "*" or origin.startswith("*"):
                raise ValueError(
                    "CORS_ALLOWED_ORIGINS must not contain wildcards. List explicit origins."
                )
            if origin and "://" not in origin:
                raise ValueError(
                    f"CORS origin {origin!r} is not a valid absolute origin. "
                    "Use the form https://app.example.com."
                )
        return normalised

    @field_validator("allowed_hosts")
    @classmethod
    def _validate_hosts(cls, value: list[str]) -> list[str]:
        return [host.strip().lower() for host in value if host.strip()]

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}:
            raise ValueError(f"Unsupported LOG_LEVEL {value!r}")
        return level

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: str) -> str:
        if value.startswith("sqlite"):
            # SQLite is supported for throwaway experiments only. It cannot
            # satisfy the constraints, partial indexes and triggers this schema
            # relies on, so it is rejected everywhere.
            raise ValueError("SQLite is not supported. Use PostgreSQL for every environment.")
        return value

    @model_validator(mode="after")
    def _validate_relationships(self) -> Settings:
        if self.password_max_length < self.password_min_length:
            raise ValueError("PASSWORD_MAX_LENGTH must be >= PASSWORD_MIN_LENGTH")
        if self.refresh_token_absolute_lifetime_days < self.refresh_token_expire_days:
            raise ValueError(
                "REFRESH_TOKEN_ABSOLUTE_LIFETIME_DAYS must be >= REFRESH_TOKEN_EXPIRE_DAYS"
            )
        if self.max_upload_size_bytes > 25 * 1024 * 1024:
            raise ValueError(
                "MAX_UPLOAD_SIZE_BYTES above 25 MiB is not supported; evidence files "
                "must be transferred directly to object storage for larger payloads."
            )
        if self.rate_limit_backend == "redis" and not self.redis_url.get_secret_value():
            raise ValueError("REDIS_URL is required when RATE_LIMIT_BACKEND=redis")
        if self.storage_backend == "s3":
            if not self.storage_bucket:
                raise ValueError("STORAGE_BUCKET is required when STORAGE_BACKEND=s3")
            if not self.storage_access_key.get_secret_value():
                raise ValueError("STORAGE_ACCESS_KEY is required when STORAGE_BACKEND=s3")
            if not self.storage_secret_key.get_secret_value():
                raise ValueError("STORAGE_SECRET_KEY is required when STORAGE_BACKEND=s3")
        return self

    @model_validator(mode="after")
    def _validate_production_posture(self) -> Settings:
        """Fail fast on production configuration that would be insecure.

        This is a security control (OWASP A05), not a convenience check: it is
        far better to refuse to boot than to serve traffic with a wildcard CORS
        policy, a development secret, or an interactive traceback.
        """
        if self.app_env != "production":
            return self

        problems: list[str] = []

        if self.debug:
            problems.append("DEBUG must be false in production.")

        if not self.secret_key.get_secret_value():
            problems.append("SECRET_KEY is required in production.")
        if not self.jwt_secret.get_secret_value():
            problems.append("JWT_SECRET is required in production.")

        for label, secret in (
            ("SECRET_KEY", self.secret_key),
            ("JWT_SECRET", self.jwt_secret),
        ):
            raw = secret.get_secret_value()
            if raw and len(raw) < MIN_SECRET_KEY_LENGTH:
                problems.append(f"{label} must be at least {MIN_SECRET_KEY_LENGTH} characters.")
            if raw and raw in INSECURE_PLACEHOLDER_SECRETS:
                problems.append(f"{label} still holds a placeholder value.")

        if self.secret_key.get_secret_value() == self.jwt_secret.get_secret_value():
            problems.append(
                "SECRET_KEY and JWT_SECRET must differ so that a compromise of one "
                "does not enable forging the other."
            )

        if not self.password_policy_enforced:
            problems.append("PASSWORD_POLICY_ENFORCED must be true in production.")

        if not self.cors_allowed_origins:
            problems.append(
                "CORS_ALLOWED_ORIGINS must list the explicit frontend origins in production."
            )

        if self.rate_limit_enabled is False:
            problems.append("RATE_LIMIT_ENABLED must be true in production.")

        if self.database_echo:
            problems.append("DATABASE_ECHO must be false in production.")

        if self.sentry_dsn.get_secret_value():
            problems.append(
                "SENTRY_DSN is set but no Sentry integration is wired up in this "
                "milestone; unset it or add the integration before deploying."
            )

        if problems:
            raise ValueError(
                "Refusing to start with an unsafe production configuration:\n  - "
                + "\n  - ".join(problems)
            )
        return self

    @model_validator(mode="after")
    def _apply_environment_defaults(self) -> Settings:
        """Narrow permissive development defaults as we approach production.

        Documentation and debug tooling are disabled by default in production
        so that an operator must take a deliberate, visible action to expose
        them.
        """
        if self.app_env == "production" and self.enable_docs is True:
            object.__setattr__(self, "enable_docs", False)
        if self.app_env == "development" and self.enable_docs is False:
            # Explicit opt-out is respected in development too.
            pass
        return self

    # ================================================================ #
    # Derived properties                                               #
    # ================================================================ #

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_testing(self) -> bool:
        return self.app_env == "test"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @property
    def enforce_password_policy(self) -> bool:
        """Password rules always apply in production, regardless of the flag."""
        return self.is_production or self.password_policy_enforced

    @property
    def session_cookie_secure(self) -> bool:
        """Cookies issued by this API must only travel over TLS in production."""
        return self.is_production

    @property
    def max_upload_size_display(self) -> str:
        megabytes = self.max_upload_size_bytes / (1024 * 1024)
        return f"{megabytes:.0f}MB" if megabytes >= 1 else f"{self.max_upload_size_bytes}B"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings` singleton.

    Cached so that configuration is parsed once. Tests clear the cache with
    ``get_settings.cache_clear()`` after mutating the environment.
    """
    return Settings()
