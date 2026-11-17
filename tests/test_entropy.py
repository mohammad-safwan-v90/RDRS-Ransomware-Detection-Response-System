"""
Unit tests for Shannon Entropy calculation using standard library unittest.
"""

import unittest
import os
import tempfile
from rdrs.app.core.entropy import (
    calculate_shannon_entropy,
    calculate_file_entropy,
    is_suspicious_entropy
)


class TestEntropyCalculator(unittest.TestCase):
    def test_empty_bytes_entropy(self):
        self.assertEqual(calculate_shannon_entropy(b""), 0.0)

    def test_uniform_bytes_entropy(self):
        data = b"A" * 100
        self.assertEqual(calculate_shannon_entropy(data), 0.0)

    def test_plain_text_entropy(self):
        data = b"Hello world! This is a simple defensive ransomware detector test string."
        entropy = calculate_shannon_entropy(data)
        self.assertTrue(3.0 <= entropy <= 5.0)
        self.assertFalse(is_suspicious_entropy(entropy, threshold=7.2))

    def test_random_encrypted_bytes_entropy(self):
        random_bytes = os.urandom(1024)
        entropy = calculate_shannon_entropy(random_bytes)
        self.assertTrue(entropy > 7.2)
        self.assertTrue(is_suspicious_entropy(entropy, threshold=7.2))

    def test_file_entropy_sampling(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"Normal plain text content inside temporary test file.")
            tmp_path = tmp.name

        try:
            entropy = calculate_file_entropy(tmp_path)
            self.assertTrue(3.0 <= entropy <= 5.0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_nonexistent_file_entropy(self):
        self.assertEqual(calculate_file_entropy("non_existent_file_999.xyz"), 0.0)


if __name__ == '__main__':
    unittest.main()
