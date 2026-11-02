import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="clamtotal-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["UPLOAD_DIR"] = str(_tmp / "uploads")
os.environ["CLAM_MODE"] = "cli"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.scanner import ScanResult, get_scanner  # noqa: E402

Base.metadata.create_all(engine)


class FakeScanner:
    engine = "ClamAV (fake)"

    def __init__(self) -> None:
        self.calls = 0

    def scan(self, data: bytes) -> ScanResult:
        self.calls += 1
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
            return ScanResult(
                "infected", "Win.Test.EICAR_HDB-1", self.engine, "stdin: Win.Test.EICAR_HDB-1 FOUND"
            )
        return ScanResult("clean", None, self.engine, "stdin: OK")


fake_scanner = FakeScanner()
app.dependency_overrides[get_scanner] = lambda: fake_scanner


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fake() -> FakeScanner:
    return fake_scanner
