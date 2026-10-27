import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.logsentinel.main", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_help():
    result = run_cli("--help")

    assert result.returncode == 0
    assert "--input" in result.stdout


def test_valid_file():
    result = run_cli("--input", "data/security.log")

    assert result.returncode == 0
    assert "Detected alerts:" in result.stdout


def test_missing_file():
    result = run_cli("--input", "data/does_not_exist.log")

    assert result.returncode == 2
    assert "Log file not found" in result.stderr


def test_directory_instead_of_file():
    result = run_cli("--input", "data/")

    assert result.returncode == 2
    assert "Path is not a file" in result.stderr
