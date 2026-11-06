from app.scanner import ScanResult


class FakeScanner:
    engine = "ClamAV (fake)"

    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "ClamAV 1.0.0 (fake)"

    def scan(self, data: bytes, path=None) -> ScanResult:
        self.calls += 1
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
            return ScanResult(
                "infected", "Win.Test.EICAR_HDB-1", self.engine, "stdin: Win.Test.EICAR_HDB-1 FOUND"
            )
        return ScanResult("clean", None, self.engine, "stdin: OK")


fake_scanner = FakeScanner()
