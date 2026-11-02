from fakes import fake_scanner

from app.db import SessionLocal
from app.main import _scan_and_store


def test_scan_and_store_returns_cache_on_second_call():
    with SessionLocal() as db:
        content = b"direct scan store call"
        scan1, cached1 = _scan_and_store(db, fake_scanner, content, "direct.bin", rescan=False)
        assert cached1 is False
        scan2, cached2 = _scan_and_store(db, fake_scanner, content, "direct.bin", rescan=False)
        assert cached2 is True
        assert scan2.sha256 == scan1.sha256
        assert scan2.status == "done"
