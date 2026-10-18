import hashlib
from pathlib import Path


def calculate_sha256(file_path: str | Path) -> str:
    """Calculate the SHA-256 digest of a file."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    digest = hashlib.sha256()

    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def verify_sha256(file_path: str | Path, expected_sha256: str) -> bool:
    """Check whether a file matches its expected SHA-256 digest."""
    if len(expected_sha256) != 64:
        return False

    try:
        int(expected_sha256, 16)
    except ValueError:
        return False

    actual_sha256 = calculate_sha256(file_path)
    return actual_sha256.lower() == expected_sha256.lower()
