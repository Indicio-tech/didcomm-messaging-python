import subprocess
from pathlib import Path

import pytest


def pytest_collect_file(parent, file_path: Path):
    """Collect Python files in examples/ as test items."""
    if file_path.suffix == ".py" and file_path.name not in ("conftest.py",):
        return ExampleFile.from_parent(parent, path=file_path)


class ExampleFile(pytest.File):
    """pytest collector for example scripts."""

    def collect(self):
        yield ExampleItem.from_parent(self, name=self.path.stem)


class ExampleItem(pytest.Item):
    """pytest item that runs an example script."""

    def runtest(self):
        result = subprocess.run(
            ["python", str(self.path)],
            capture_output=True,
            text=True,
            cwd=self.path.parent,
        )
        if result.returncode != 0:
            raise ExampleFailedError(
                f"Example {self.name} failed with code {result.returncode}\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            )

    def reportinfo(self):
        return self.path, 0, f"Example: {self.path.name}"


class ExampleFailedError(Exception):
    """Raised when an example script fails to run."""
