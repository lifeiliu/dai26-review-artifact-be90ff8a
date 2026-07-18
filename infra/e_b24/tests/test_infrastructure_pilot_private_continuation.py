from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "strict"
    / "infrastructure_pilot_private_continuation.py"
)
SPEC = importlib.util.spec_from_file_location("private_continuation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PrivateContinuationTests(unittest.TestCase):
    def test_base_pilot_loader_rejects_missing_module(self) -> None:
        with self.assertRaises(FileNotFoundError):
            MODULE._load_base(Path("/definitely/missing/infrastructure_pilot.py"))

    def test_source_contains_no_revocation_or_effect_invocation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("logout", source.lower().replace("no logout", ""))
        self.assertNotIn("pending-events", source)
        self.assertNotIn("/mcp", source)
        self.assertIn("receiver-b/stream", source)
        self.assertNotIn("receiver-a/stream", source)


if __name__ == "__main__":
    unittest.main()
