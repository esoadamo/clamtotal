import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="clamtotal-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["UPLOAD_DIR"] = str(_tmp / "uploads")
os.environ["URL_BLOCKLIST_DIR"] = str(_tmp / "blocklists")
os.environ["CLAM_MODE"] = "cli"

import pytest  # noqa: E402
from fakes import FakeScanner, fake_scanner  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.scanner import get_scanner  # noqa: E402

Base.metadata.create_all(engine)

app.dependency_overrides[get_scanner] = lambda: fake_scanner
# background scan tasks call get_scanner() directly, so patch the module global too
import app.main as main_module  # noqa: E402

main_module.get_scanner = lambda: fake_scanner  # ty: ignore[invalid-assignment]


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fake() -> FakeScanner:
    return fake_scanner
