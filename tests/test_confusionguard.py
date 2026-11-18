import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import confusionguard as cg


class TestDistance(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(cg.osa_distance("requests", "requests"), 0)

    def test_adjacent_transposition(self):
        self.assertEqual(cg.osa_distance("axios", "axois"), 1)
        self.assertEqual(cg.osa_distance("requests", "reqeusts"), 1)

    def test_insertion_and_deletion(self):
        self.assertEqual(cg.osa_distance("express", "expres"), 1)
        self.assertEqual(cg.osa_distance("lodash", "lodahs"), 1)


class TestTyposquat(unittest.TestCase):
    def test_flags_transposition(self):
        self.assertEqual(cg.find_typosquat("axois", "npm"), "axios")

    def test_exact_popular_is_clean(self):
        self.assertIsNone(cg.find_typosquat("axios", "npm"))
        self.assertIsNone(cg.find_typosquat("requests", "pypi"))

    def test_scoped_official_name_is_clean(self):
        self.assertIsNone(cg.find_typosquat("@types/express", "npm"))

    def test_legit_plugin_not_flagged(self):
        self.assertIsNone(cg.find_typosquat("express-session", "npm"))
        self.assertIsNone(cg.find_typosquat("python-dateutil", "pypi"))

    def test_separator_trick(self):
        self.assertEqual(cg.find_typosquat("req-ue-sts", "pypi"), "requests")

    def test_unknown_ecosystem(self):
        self.assertIsNone(cg.find_typosquat("axois", "cargo"))


class TestParsing(unittest.TestCase):
    def test_requirements(self):
        text = """
        # comment
        -r base.txt
        -e .
        requests==2.31.0
        PyYAML>=6.0 ; python_version >= "3.9"
        flask[async]
        git+https://example.com/x.git
        """
        pairs = cg.parse_requirements(text)
        names = [n.lower() for n, _ in pairs]
        self.assertEqual(names, ["requests", "pyyaml", "flask"])
        self.assertEqual(dict((n.lower(), v) for n, v in pairs)["requests"], "==2.31.0")

    def test_package_json(self):
        data = {"dependencies": {"express": "^4.0.0"}, "devDependencies": {"jest": "^29"}}
        pairs = dict(cg.parse_package_json(data))
        self.assertEqual(pairs, {"express": "^4.0.0", "jest": "^29"})

    def test_pyproject(self):
        data = {
            "project": {
                "dependencies": ["requests>=2", "uvicorn[standard]==0.30"],
                "optional-dependencies": {"dev": ["pytest>=8"]},
            }
        }
        names = [n for n, _ in cg.parse_pyproject(data)]
        self.assertEqual(names, ["requests", "uvicorn", "pytest"])

    def test_unsupported_manifest(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            path = Path(fh.name)
            fh.write("{}")
        try:
            with self.assertRaises(ValueError):
                cg.collect_dependencies(path)
        finally:
            path.unlink()


class TestScoring(unittest.TestCase):
    def test_missing_is_critical(self):
        score, reasons = cg.assess({"exists": False}, None)
        self.assertGreaterEqual(score, 70)
        self.assertEqual(cg.level_for(score), "critical")
        self.assertTrue(any("not found" in r for r in reasons))

    def test_typo_alone_is_high(self):
        score, _ = cg.assess({"exists": True}, "axios")
        self.assertEqual(cg.level_for(score), "high")

    def test_missing_and_typo_caps_at_100(self):
        score, _ = cg.assess({"exists": False}, "axios")
        self.assertEqual(score, 100)

    def test_clean_recent_package(self):
        meta = {"exists": True, "age_days": 2000, "week_downloads": 5_000_000, "maintainers": 4, "has_repo": True}
        score, reasons = cg.assess(meta, None)
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_lookup_failure_does_not_flag_missing(self):
        score, reasons = cg.assess(None, None, lookup_failed=True)
        self.assertEqual(score, 0)
        self.assertTrue(any("lookup failed" in r for r in reasons))

    def test_level_boundaries(self):
        self.assertEqual(cg.level_for(0), "info")
        self.assertEqual(cg.level_for(10), "low")
        self.assertEqual(cg.level_for(25), "medium")
        self.assertEqual(cg.level_for(45), "high")
        self.assertEqual(cg.level_for(70), "critical")


class TestScanOffline(unittest.TestCase):
    def test_offline_scan_finds_typosquat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("reqeusts==2.31.0\nflask\n", encoding="utf-8")
            findings = cg.scan(root, offline=True)
            self.assertEqual(len(findings), 2)
            top = findings[0]
            self.assertEqual(top["name"], "reqeusts")
            self.assertEqual(top["level"], "high")

    def test_main_exit_code_on_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({"dependencies": {"axois": "^1.0.0"}}), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cg.main([str(root), "--offline", "--fail-on", "high"])
            self.assertEqual(code, 2)
            self.assertIn("axois", buf.getvalue())

    def test_main_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cg.main([str(root), "--offline", "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(buf.getvalue())[0]["name"], "requests")


if __name__ == "__main__":
    unittest.main()
