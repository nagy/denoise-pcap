from pathlib import Path

import hy
import pytest

# For the side-effect of allowing import of Hy programs.


def pytest_collect_file(parent, path):
    if path.basename.startswith("test_") and path.ext == ".hy":
        return pytest.Module.from_parent(parent, path=Path(path))
