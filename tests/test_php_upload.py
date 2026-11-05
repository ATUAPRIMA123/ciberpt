import tempfile
import unittest
from pathlib import Path
from ciberpt.core.models import Severity
from ciberpt.modules.appsec.php_upload import PHPUploadScanner


class TestPHPUploadScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = PHPUploadScanner()

    def test_unrestricted_upload_detection(self):
        code = """<?php
        $target_dir = "uploads/";
        $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
        move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file);
        ?>"""
        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
            f.write(code)
            f_path = Path(f.name)

        try:
            findings = self.scanner.audit_file(f_path)
            unrestricted = [f for f in findings if f.id == "SEC-APPSEC-PHP-UNRESTRICTED-UPLOAD"]
            self.assertEqual(len(unrestricted), 1)
            self.assertEqual(unrestricted[0].severity, Severity.CRITICAL)
        finally:
            f_path.unlink()

    def test_blacklist_filter_detection(self):
        code = """<?php
        $ext = pathinfo($_FILES["file"]["name"], PATHINFO_EXTENSION);
        if ($ext == "php") {
            die("Extensao proibida");
        }
        ?>"""
        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
            f.write(code)
            f_path = Path(f.name)

        try:
            findings = self.scanner.audit_file(f_path)
            blacklist = [f for f in findings if f.id == "SEC-APPSEC-PHP-BLACKLIST-FILTER"]
            self.assertEqual(len(blacklist), 1)
            self.assertEqual(blacklist[0].severity, Severity.HIGH)
        finally:
            f_path.unlink()

    def test_client_mime_type_trust(self):
        code = """<?php
        if ($_FILES["file"]["type"] == "image/png") {
            move_uploaded_file($_FILES["file"]["tmp_name"], "uploads/test.png");
        }
        ?>"""
        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
            f.write(code)
            f_path = Path(f.name)

        try:
            findings = self.scanner.audit_file(f_path)
            mime_findings = [f for f in findings if f.id == "SEC-APPSEC-PHP-TRUST-CLIENT-MIME"]
            self.assertEqual(len(mime_findings), 1)
            self.assertEqual(mime_findings[0].severity, Severity.MEDIUM)
        finally:
            f_path.unlink()

    def test_secure_upload_implementation(self):
        code = """<?php
        $allowed_extensions = ['jpg', 'png', 'pdf'];
        $ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, $allowed_extensions)) {
            die('Invalid file extension');
        }
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
        if ($mime !== 'image/jpeg' && $mime !== 'image/png') {
            die('Invalid MIME type');
        }
        $safe_name = bin2hex(random_bytes(16)) . '.' . $ext;
        move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $safe_name);
        ?>"""
        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
            f.write(code)
            f_path = Path(f.name)

        try:
            findings = self.scanner.audit_file(f_path)
            self.assertEqual(len(findings), 0)
        finally:
            f_path.unlink()


if __name__ == "__main__":
    unittest.main()
