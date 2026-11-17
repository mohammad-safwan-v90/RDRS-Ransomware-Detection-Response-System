import unittest
import os
import shutil
import tempfile
from rdrs.app.detectors.detection_engine import DetectionEngine
from rdrs.app.core.config import config

class TestQuarantineSecurity(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory structure for testing
        self.test_dir = tempfile.mkdtemp()
        self.sandbox = os.path.join(self.test_dir, "sandbox")
        self.sandbox_backup = os.path.join(self.test_dir, "sandbox_backup")
        self.outside = os.path.join(self.test_dir, "outside")
        self.quarantine = os.path.join(self.test_dir, "quarantine")
        
        os.makedirs(self.sandbox)
        os.makedirs(self.sandbox_backup)
        os.makedirs(self.outside)
        os.makedirs(self.quarantine)
        
        # Override config watch_paths and quarantine dir
        self.original_watch_paths = config.watch_paths
        self.original_quarantine_dir = config.get("quarantine", {}).get("storage_dir", "./quarantine")
        
        # We need to monkeypatch the config object properties if possible, 
        # but since it's a property we might need to modify the underlying _data
        config._data["monitoring"]["watch_paths"] = [self.sandbox]
        config._data["quarantine"]["storage_dir"] = self.quarantine
        
        self.engine = DetectionEngine()

    def tearDown(self):
        # Restore original config
        config._data["monitoring"]["watch_paths"] = self.original_watch_paths
        config._data["quarantine"]["storage_dir"] = self.original_quarantine_dir
        shutil.rmtree(self.test_dir)

    def test_valid_sandbox_file(self):
        file_path = os.path.join(self.sandbox, "valid.txt")
        with open(file_path, "w") as f:
            f.write("valid content")
        
        results = self.engine.quarantine_evidence([file_path])
        self.assertEqual(len(results), 1)
        self.assertTrue(os.path.exists(results[0]))

    def test_outside_directory(self):
        file_path = os.path.join(self.outside, "secret.txt")
        with open(file_path, "w") as f:
            f.write("secret content")
        
        results = self.engine.quarantine_evidence([file_path])
        self.assertEqual(len(results), 0, "Should reject files in outside directory")

    def test_parent_traversal(self):
        # Attempt to access outside file via traversal from sandbox
        file_path = os.path.join(self.sandbox, "..", "outside", "secret.txt")
        # Ensure the file exists
        outside_file = os.path.join(self.outside, "secret.txt")
        with open(outside_file, "w") as f:
            f.write("secret content")
            
        results = self.engine.quarantine_evidence([file_path])
        self.assertEqual(len(results), 0, "Should reject parent traversal attacks")

    def test_sibling_prefix_attack(self):
        # Sandbox is .../sandbox, Sibling is .../sandbox_backup
        file_path = os.path.join(self.sandbox_backup, "backup.txt")
        with open(file_path, "w") as f:
            f.write("backup content")
            
        results = self.engine.quarantine_evidence([file_path])
        self.assertEqual(len(results), 0, "Should reject sibling directory prefix attacks")

    def test_symlink_pointing_outside(self):
        outside_file = os.path.join(self.outside, "secret.txt")
        with open(outside_file, "w") as f:
            f.write("secret content")
            
        link_path = os.path.join(self.sandbox, "malicious_link")
        try:
            os.symlink(outside_file, link_path)
        except OSError:
            self.skipTest("Symlinks not supported on this platform/filesystem")
            
        results = self.engine.quarantine_evidence([link_path])
        self.assertEqual(len(results), 0, "Should reject symlinks pointing outside the sandbox")

    def test_nonexistent_path(self):
        file_path = os.path.join(self.sandbox, "ghost.txt")
        results = self.engine.quarantine_evidence([file_path])
        self.assertEqual(len(results), 0, "Should reject nonexistent files")

    def test_duplicate_quarantine(self):
        file_path = os.path.join(self.sandbox, "duplicate.txt")
        with open(file_path, "w") as f:
            f.write("content")
            
        # Passing the same file twice in one call
        results = self.engine.quarantine_evidence([file_path, file_path])
        self.assertEqual(len(results), 1, "Should not create duplicate quarantine entries in a single batch")

if __name__ == "__main__":
    unittest.main()
