"""Tests for the container entrypoint and the Docker deployment contract.

These assert things that are cheap to check and expensive to discover in
production: that migrations run before the server, that a failed migration stops
the container instead of starting it, and that the Dockerfile still says what the
deployment documentation claims it says.

They deliberately do **not** try to prove that the migrations work. That is
verified by running ``alembic upgrade head`` against a real PostgreSQL database,
which needs a live server and cannot be faked convincingly — a mocked engine
would pass whether or not the schema were correct. See ``docs/deployment.md``
for the manual verification procedure.

What is tested here is the *wrapper* around those migrations: the ordering, the
failure behaviour, and the parts of the Dockerfile that are easy to regress with
an innocent-looking edit.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import textwrap

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
ENTRYPOINT = REPO_ROOT / "docker" / "entrypoint.sh"

pytestmark = [pytest.mark.unit]

# The Uvicorn invocation the entrypoint must preserve. Rendered against the
# previous inline CMD: a change to any of these is a behaviour change to how the
# API binds, how many workers exist, or how the platform's proxy headers are
# trusted, and none of them is worth making casually.
EXPECTED_UVICORN_ARGS = (
    "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} "
    "--workers 1 --proxy-headers --forwarded-allow-ips='*'"
)


# --------------------------------------------------------------------------- #
# Entrypoint: static contract                                                  #
# --------------------------------------------------------------------------- #
class TestEntrypointContract:
    """The script's guarantees, read from the file rather than by running it."""

    @pytest.fixture(scope="class")
    def script(self) -> str:
        return ENTRYPOINT.read_text(encoding="utf-8")

    def test_entrypoint_exists(self) -> None:
        assert ENTRYPOINT.is_file(), "docker/entrypoint.sh must exist"

    def test_is_executable(self) -> None:
        """Git must carry the exec bit, or the CMD fails with permission denied."""
        mode = ENTRYPOINT.stat().st_mode
        assert mode & stat.S_IXUSR, "entrypoint.sh must be executable by its owner"

    def test_uses_posix_sh_not_bash(self, script: str) -> None:
        """python:3.12-slim-bookworm has no bash. A bash shebang cannot start."""
        first_line = script.splitlines()[0]
        assert first_line.strip() == "#!/bin/sh", f"shebang must be #!/bin/sh, got {first_line!r}"

    def test_fails_fast(self, script: str) -> None:
        """A migration that half-fails must stop the boot, not be ignored."""
        assert re.search(r"^set -e\s*$", script, re.MULTILINE), (
            "entrypoint must use `set -e` so a failed migration aborts startup"
        )

    def test_runs_migrations(self, script: str) -> None:
        assert "alembic upgrade head" in script

    def test_uvicorn_is_the_final_command_and_uses_exec(self, script: str) -> None:
        """`exec` makes Uvicorn PID 1 so it receives SIGTERM directly."""
        exec_line = next(
            (line for line in script.splitlines() if line.startswith("exec uvicorn")),
            None,
        )
        assert exec_line is not None, "Uvicorn must be started with exec"
        assert exec_line.strip() == EXPECTED_UVICORN_ARGS, (
            f"Uvicorn arguments changed.\n  expected: {EXPECTED_UVICORN_ARGS}\n"
            f"  found:    {exec_line.strip()}"
        )

    def test_migrations_run_before_uvicorn(self, script: str) -> None:
        """Ordering is the whole point: serving traffic against no schema fails
        every database-backed request while /health/ready still reports 200."""
        migration_at = script.index("alembic upgrade head")
        exec_at = script.index("exec uvicorn")
        assert migration_at < exec_at, "migrations must run before Uvicorn starts"

    def test_no_database_url_is_hard_coded(self, script: str) -> None:
        """Credentials must come from DATABASE_URL via Settings, never the script."""
        assert not re.search(r"postgresql(\+psycopg)?://", script), (
            "entrypoint must not contain a database URL; it reads DATABASE_URL"
        )
        for marker in ("PASSWORD=", "SECRET_KEY=", "postgresql://postgres"):
            assert marker not in script, f"entrypoint must not embed {marker!r}"

    def test_no_destructive_alembic_commands(self, script: str) -> None:
        for forbidden in ("downgrade", "drop_all", "DROP DATABASE", "reset"):
            assert forbidden not in script, f"entrypoint must not contain {forbidden!r}"

    def test_seed_is_opt_in_only(self, script: str) -> None:
        """The seed rewrites all reference rows on every run, so it must never
        happen unless an operator asked for it by name."""
        seed_calls = [line for line in script.splitlines() if "app.db.seed" in line]
        assert seed_calls, "the documented opt-in seed must still be present"
        for line in seed_calls:
            assert "--catalogues-only" in line, (
                "only the catalogues-only seed is safe in production; it never "
                f"creates the sample accounts. Found: {line.strip()!r}"
            )
        assert "RUN_CATALOGUE_SEED" in script, (
            "the seed must be gated behind an explicit environment variable"
        )


# --------------------------------------------------------------------------- #
# Entrypoint: behaviour, executed against fakes                                #
# --------------------------------------------------------------------------- #
class TestEntrypointBehaviour:
    """Run the script with a stub `alembic` and a stub `uvicorn` on PATH.

    No database and no server: this checks control flow, which is what can be
    tested without one. The real migrations are verified by running them.
    """

    @pytest.fixture
    def stub_bin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """A PATH containing fake `alembic`, `uvicorn` and `python`."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        log = tmp_path / "calls.log"

        def install(name: str, body: str, exit_code: int = 0) -> Path:
            script = bin_dir / name
            script.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    echo "{name} $*" >> {log}
                    exit {exit_code}
                    """
                ),
                encoding="utf-8",
            )
            script.chmod(0o755)
            return script

        install("alembic", "", exit_code=0)
        install("uvicorn", "")
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        return log

    @pytest.fixture
    def script_copy(self, tmp_path: Path) -> Path:
        """The real script, copied so its dirname-relative APP_ROOT is the repo.

        Copying to <tmp>/docker/entrypoint.sh would resolve APP_ROOT to the temp
        directory, so it is copied into a tmp tree that also holds the repo's
        alembic.ini and alembic/ directory.
        """
        app_root = tmp_path / "app"
        (app_root / "docker").mkdir(parents=True)
        shutil.copy2(ENTRYPOINT, app_root / "docker" / "entrypoint.sh")
        shutil.copy2(REPO_ROOT / "alembic.ini", app_root / "alembic.ini")
        shutil.copytree(REPO_ROOT / "alembic", app_root / "alembic")
        return app_root / "docker" / "entrypoint.sh"

    def test_migration_failure_prevents_uvicorn_from_starting(
        self, script_copy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The critical guarantee. A container that starts Uvicorn after a failed
        migration serves 500s from every database-backed route."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        log = tmp_path / "calls.log"

        (bin_dir / "alembic").write_text(
            f'#!/bin/sh\necho "alembic $*" >> {log}\nexit 1\n', encoding="utf-8"
        )
        (bin_dir / "uvicorn").write_text(
            f'#!/bin/sh\necho "uvicorn $*" >> {log}\nexit 0\n', encoding="utf-8"
        )
        for name in ("alembic", "uvicorn"):
            (bin_dir / name).chmod(0o755)

        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        monkeypatch.setenv("MIGRATION_ATTEMPTS", "2")
        monkeypatch.setenv("MIGRATION_RETRY_DELAY", "0")

        result = subprocess.run(  # noqa: S603 - fixed local fixture paths only
            # Absolute path, and the only arguments are this test's own fixture
            # paths and fixed environment overrides - nothing from a request.
            ["/bin/sh", str(script_copy)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode != 0, "a failed migration must fail the container"
        assert "uvicorn" not in log.read_text(encoding="utf-8"), (
            "Uvicorn must not start when the migration failed"
        )

    def test_retries_a_failing_migration_then_gives_up(
        self, script_copy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A suspended free-tier database resumes after a few seconds, so the
        first failure is not fatal — but the bound is real."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        log = tmp_path / "calls.log"
        (bin_dir / "alembic").write_text(
            f'#!/bin/sh\necho "alembic $*" >> {log}\nexit 1\n', encoding="utf-8"
        )
        (bin_dir / "uvicorn").write_text(
            f'#!/bin/sh\necho "uvicorn $*" >> {log}\nexit 0\n', encoding="utf-8"
        )
        for name in ("alembic", "uvicorn"):
            (bin_dir / name).chmod(0o755)

        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        monkeypatch.setenv("MIGRATION_ATTEMPTS", "3")
        monkeypatch.setenv("MIGRATION_RETRY_DELAY", "0")

        result = subprocess.run(  # noqa: S603 - fixed local fixture paths only
            # Absolute path, and the only arguments are this test's own fixture
            # paths and fixed environment overrides - nothing from a request.
            ["/bin/sh", str(script_copy)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        calls = log.read_text(encoding="utf-8").count("alembic")
        assert calls == 3, f"expected 3 bounded attempts, saw {calls}"
        assert result.returncode != 0

    def test_successful_migration_starts_uvicorn_with_the_expected_arguments(
        self, script_copy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        log = tmp_path / "calls.log"
        (bin_dir / "alembic").write_text(
            f'#!/bin/sh\necho "alembic $*" >> {log}\nexit 0\n', encoding="utf-8"
        )
        (bin_dir / "uvicorn").write_text(
            f'#!/bin/sh\necho "uvicorn $*" >> {log}\nexit 0\n', encoding="utf-8"
        )
        for name in ("alembic", "uvicorn"):
            (bin_dir / name).chmod(0o755)

        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        monkeypatch.setenv("MIGRATION_RETRY_DELAY", "0")

        result = subprocess.run(  # noqa: S603 - fixed local fixture paths only
            # Absolute path, and the only arguments are this test's own fixture
            # paths and fixed environment overrides - nothing from a request.
            ["/bin/sh", str(script_copy)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        calls = log.read_text(encoding="utf-8")
        assert result.returncode == 0, result.stderr
        assert "alembic upgrade head" in calls
        # The stub echoes its arguments, so the real invocation is asserted here.
        assert "app.main:app --host 0.0.0.0 --port" in calls
        assert "--workers 1 --proxy-headers" in calls

    def test_honours_the_render_port_variable(
        self, script_copy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Render always sets PORT; a hard-coded 8080 would not be reachable."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        log = tmp_path / "calls.log"
        for name in ("alembic", "uvicorn"):
            (bin_dir / name).write_text(
                f'#!/bin/sh\necho "{name} $*" >> {log}\nexit 0\n', encoding="utf-8"
            )
            (bin_dir / name).chmod(0o755)

        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        monkeypatch.setenv("MIGRATION_RETRY_DELAY", "0")
        monkeypatch.setenv("PORT", "12345")

        subprocess.run(  # noqa: S603 - fixed local fixture paths only
            ["/bin/sh", str(script_copy)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert "--port 12345" in log.read_text(encoding="utf-8")

    def test_seed_does_not_run_unless_explicitly_requested(
        self, script_copy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default startup must write nothing to the reference tables."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        log = tmp_path / "calls.log"
        for name in ("alembic", "uvicorn"):
            (bin_dir / name).write_text(
                f'#!/bin/sh\necho "{name} $*" >> {log}\nexit 0\n', encoding="utf-8"
            )
            (bin_dir / name).chmod(0o755)

        (bin_dir / "python").write_text(
            f'#!/bin/sh\necho "python $*" >> {log}\nexit 0\n', encoding="utf-8"
        )
        (bin_dir / "python").chmod(0o755)

        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        monkeypatch.setenv("MIGRATION_RETRY_DELAY", "0")
        monkeypatch.delenv("RUN_CATALOGUE_SEED", raising=False)

        subprocess.run(  # noqa: S603 - fixed local fixture paths only
            ["/bin/sh", str(script_copy)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert "app.db.seed" not in log.read_text(encoding="utf-8"), (
            "the catalogue seed must not run by default"
        )


# --------------------------------------------------------------------------- #
# Dockerfile contract                                                          #
# --------------------------------------------------------------------------- #
class TestDockerfile:
    """The Dockerfile is deployment configuration, and it regresses silently."""

    @pytest.fixture(scope="class")
    def dockerfile(self) -> str:
        return DOCKERFILE.read_text(encoding="utf-8")

    def test_cmd_runs_the_entrypoint(self, dockerfile: str) -> None:
        assert re.search(r'^CMD \["/app/docker/entrypoint\.sh"\]$', dockerfile, re.M), (
            "CMD must invoke the entrypoint"
        )

    def test_uvicorn_is_no_longer_an_inline_cmd(self, dockerfile: str) -> None:
        """Keeping both would mean two sources of truth for how the API starts."""
        cmd_lines = [line for line in dockerfile.splitlines() if line.startswith("CMD ")]
        assert len(cmd_lines) == 1, f"expected one CMD, found {cmd_lines}"
        assert "uvicorn" not in cmd_lines[0], (
            "the inline Uvicorn CMD must be replaced, not kept alongside"
        )

    def test_copies_the_entrypoint_into_the_runtime_image(self, dockerfile: str) -> None:
        assert "docker/entrypoint.sh" in dockerfile

    def test_entrypoint_is_owned_by_the_runtime_user_and_executable(self, dockerfile: str) -> None:
        """`--chown` matches every other COPY, `--chmod` guarantees the exec bit
        survives a build that ignores the host file mode."""
        match = re.search(
            r"^COPY\s+--chown=fundipulse:fundipulse\s+--chmod=(\d{3,4})\s+"
            r"docker/entrypoint\.sh",
            dockerfile,
            re.M,
        )
        assert match, "entrypoint COPY must set --chown and --chmod"
        mode = int(match.group(1), 8)
        assert mode & stat.S_IXUSR, f"entrypoint mode {match.group(1)} is not executable"
        assert not mode & stat.S_IWOTH, "the entrypoint must not be world-writable"

    def test_keeps_the_multi_stage_builder(self, dockerfile: str) -> None:
        assert "AS builder" in dockerfile and "AS runtime" in dockerfile
        assert dockerfile.count("FROM ") >= 2

    def test_keeps_the_non_root_runtime_user(self, dockerfile: str) -> None:
        """The non-root user must remain: running the migration as root would be
        a privilege escalation for a code path that does not need it."""
        assert re.search(r"^USER fundipulse\s*$", dockerfile, re.M)
        user_lines = [line for line in dockerfile.splitlines() if line.startswith("USER ")]
        assert user_lines == ["USER fundipulse"], (
            f"the only USER instruction must be fundipulse, found {user_lines}"
        )

    def test_user_is_declared_before_the_entrypoint_is_used(self, dockerfile: str) -> None:
        assert dockerfile.index("USER fundipulse") < dockerfile.index("CMD [")

    def test_keeps_the_healthcheck(self, dockerfile: str) -> None:
        """Render probes this; removing it turns every restart into a hard failure."""
        assert "HEALTHCHECK" in dockerfile
        assert "/health/ready" in dockerfile

    def test_still_copies_the_migration_history(self, dockerfile: str) -> None:
        """Without alembic/ and alembic.ini the startup migration cannot run."""
        assert re.search(r"^COPY .*alembic/ \./alembic/$", dockerfile, re.M)
        assert re.search(r"^COPY .*alembic\.ini \./$", dockerfile, re.M)

    def test_base_images_are_unchanged(self, dockerfile: str) -> None:
        from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        assert from_lines == [
            "FROM python:3.12-slim-bookworm AS builder",
            "FROM python:3.12-slim-bookworm AS runtime",
        ], f"base images changed: {from_lines}"

    def test_no_database_url_or_secret_in_the_dockerfile(self, dockerfile: str) -> None:
        assert not re.search(r"postgresql(\+psycopg)?://", dockerfile), (
            "the Dockerfile must not carry a database URL"
        )
        for marker in ("ENV SECRET_KEY", "ENV DATABASE_URL", "PASSWORD="):
            assert marker not in dockerfile, f"Dockerfile must not contain {marker!r}"


# --------------------------------------------------------------------------- #
# Alembic configuration                                                        #
# --------------------------------------------------------------------------- #
class TestAlembicConfiguration:
    """The URL must come from Settings, or the migration would target the
    wrong database — which on a shared host means running migrations against
    someone else's data."""

    def test_alembic_ini_does_not_carry_a_url(self) -> None:
        ini = (REPO_ROOT / "alembic.ini").read_text(encoding="utf-8")
        url_lines = [line for line in ini.splitlines() if line.strip().startswith("sqlalchemy.url")]
        assert len(url_lines) == 1
        assert url_lines[0].split("=", 1)[1].strip() == "", (
            "sqlalchemy.url must be empty; env.py supplies it from Settings"
        )

    def test_env_py_resolves_the_url_from_settings(self) -> None:
        env = (REPO_ROOT / "alembic" / "env.py").read_text(encoding="utf-8")
        assert "get_settings()" in env
        assert "settings.database_url" in env
        assert not re.search(r"postgresql(\+psycopg)?://", env), (
            "env.py must not hard-code a connection string"
        )

    def test_settings_uses_the_same_database_url_variable(self) -> None:
        """The application and the migration must resolve the same setting name,
        or the container can migrate one database and serve another."""
        config = (REPO_ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
        assert re.search(r"database_url:\s*str", config)
        env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        assert "DATABASE_URL" in env_example
