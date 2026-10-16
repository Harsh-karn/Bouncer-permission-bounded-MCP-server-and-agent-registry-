"""
Bouncer: A permission-bounded MCP server and agent registry
where the forbidden write has no code path.
"""

from pathlib import Path
import sys

# Ensure repository root and src directory are in sys.path
_repo_root = Path(__file__).resolve().parent.parent.parent
_src_dir = Path(__file__).resolve().parent.parent

for _p in [str(_repo_root), str(_src_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

__version__ = "0.1.0"
