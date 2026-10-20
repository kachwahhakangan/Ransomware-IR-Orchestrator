import hashlib
import tempfile
import unittest
from pathlib import Path

from app.evidence_integrity import calculate_sha256, verify_sha256


class TestEvidenceIntegrity(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_directory.name) / "evidence.txt"
        self.file_path.write_text(
            "Sample forensic evidence",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_directory.cleanup()

    def test_calculate_sha256(self):
        expected_hash = hashlib.sha256(
            b"Sample forensic evidence"
        ).hexdigest()

        actual_hash = calculate_sha256(self.file_path)

        self.assertEqual(actual_hash, expected_hash)

    def test_verify_correct_hash(self):
        expected_hash = calculate_sha256(self.file_path)

        result = verify_sha256(self.file_path, expected_hash)

        self.assertTrue(result)

    def test_detect_modified_evidence(self):
        original_hash = calculate_sha256(self.file_path)

        self.file_path.write_text(
            "Modified forensic evidence",
            encoding="utf-8",
        )

        modified_hash = calculate_sha256(self.file_path)

        self.assertNotEqual(original_hash, modified_hash)
        self.assertFalse(
            verify_sha256(self.file_path, original_hash)
        )

    def test_missing_evidence_file(self):
        missing_file = Path(self.temp_directory.name) / "missing.txt"

        with self.assertRaises(FileNotFoundError):
            calculate_sha256(missing_file)

    def test_invalid_hash_format(self):
        result = verify_sha256(self.file_path, "invalid-hash")

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
