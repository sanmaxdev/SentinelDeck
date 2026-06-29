"""Run the dashboard's render() in a stubbed DOM to catch runtime errors
(missing functions, bad references) that Python tests and `node --check` miss.
Skips where Node.js is not installed; GitHub's runners have it.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "webui" / "render_check.js"
APP = ROOT / "src" / "sentineldeck" / "webui" / "app.js"
FIXTURE = ROOT / "tests" / "fixtures" / "dashboard_report.json"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_dashboard_render_does_not_throw():
    result = subprocess.run(
        ["node", str(HARNESS), str(APP), str(FIXTURE)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"render failed:\n{result.stderr}"
    assert "RENDER OK" in result.stdout
