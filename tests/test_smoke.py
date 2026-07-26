"""Smoke tests: config imports, the app boots against temp SQLite paths, and
the /health probe answers.

Run:  python -m pytest
"""

import os
import tempfile

import pytest

# Point storage at a temp dir BEFORE the app modules are imported.
_tmpdir = tempfile.mkdtemp(prefix="rts-smoke-")
os.environ.setdefault("SQLITE_PATH", os.path.join(_tmpdir, "runtime_security.sqlite"))
os.environ.setdefault("AUDIT_DB_PATH", os.path.join(_tmpdir, "audit_bus.sqlite"))
os.environ.setdefault("RUNTIME_SECURITY_JWT_SECRET", "smoke-test-secret")


def test_config_imports_with_writable_defaults():
    from app.config import Config

    assert str(Config.SQLITE_PATH).endswith("runtime_security.sqlite")
    assert str(Config.AUDIT_DB_PATH).endswith("audit_bus.sqlite")


def test_app_boots_and_health_answers():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("status") in ("ok", "healthy")


def test_dashboard_root_requires_a_token():
    """The dashboard is behind the admin-token gate like every other route."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        assert client.get("/").status_code in (401, 503)


def test_dashboard_root_renders_with_token():
    import os

    from fastapi.testclient import TestClient

    from app.main import app

    token = os.environ.get("RUNTIME_SECURITY_ADMIN_TOKEN", "")
    if not token:
        pytest.skip("RUNTIME_SECURITY_ADMIN_TOKEN not set")
    with TestClient(app) as client:
        resp = client.get("/", headers={"X-Security-Token": token})
        assert resp.status_code == 200
