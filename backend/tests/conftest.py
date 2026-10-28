import os
import tempfile

# Must be set before the app is imported.
_tmp = tempfile.mkdtemp(prefix="cs-test-")
os.environ.update({
    "ENVIRONMENT": "development",
    "DEMO_MODE": "true",
    "SECRET_KEY": "test-secret-key-0123456789-0123456789-abcdef",
    "SQLITE_URL": f"sqlite:///{_tmp}/test.db",
    "MFA_ENFORCED": "false",
    "OUTBOX_WORKER_ENABLED": "false",
    "COOKIE_SECURE": "false",
    "RATE_LIMIT_LOGIN_PER_MINUTE": "1000",
    "ALERT_SOC_EMAILS": '["soc@example.org"]',
})
for var in ("DATABASE_URL", "SUPABASE_DATABASE_URL"):
    os.environ.pop(var, None)

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import app
from app.services.demo_data_seeder import seed_demo_soc_data
from app.utils.ratelimit import limiter

PASSWORD = "CyberShield@2026!"
ACCOUNTS = {
    "admin": "admin@cybershield.corp",
    "secadmin": "secadmin@cybershield.corp",
    "analyst": "analyst@cybershield.corp",
    "employee": "alex.turner@enterprise-corp.com",
}


@pytest.fixture(scope="session", autouse=True)
def _database():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_demo_soc_data(db=db, force_reset=True)
    yield


@pytest.fixture(autouse=True)
def _reset_limits():
    limiter.reset()
    yield


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


def make_client() -> TestClient:
    return TestClient(app)


def login(client: TestClient, email: str, password: str = PASSWORD):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    if res.status_code == 200:
        token = client.cookies.get(settings.CSRF_COOKIE_NAME)
        if token:
            client.headers["X-CSRF-Token"] = token
    return res


def _signed_in(role: str):
    with make_client() as c:
        res = login(c, ACCOUNTS[role])
        assert res.status_code == 200, res.text
        yield c


@pytest.fixture
def anon():
    with make_client() as c:
        yield c


@pytest.fixture
def admin():
    yield from _signed_in("admin")


@pytest.fixture
def secadmin():
    yield from _signed_in("secadmin")


@pytest.fixture
def analyst():
    yield from _signed_in("analyst")


@pytest.fixture
def employee():
    yield from _signed_in("employee")


@pytest.fixture
def client(analyst):
    """Default authenticated client for feature tests."""
    return analyst
