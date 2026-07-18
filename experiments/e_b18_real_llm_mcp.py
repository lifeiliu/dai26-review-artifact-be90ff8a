"""Run the preregistered E-B18 local LLM/MCP experiment."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from revocation_propagation.real_llm_mcp_harness import main


if __name__ == "__main__":
    main()
