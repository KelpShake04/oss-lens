import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def syft_data():
    return json.loads((FIXTURES / "syft-demo.json").read_text(encoding="utf-8"))


@pytest.fixture
def grype_data():
    return json.loads((FIXTURES / "grype-demo.json").read_text(encoding="utf-8"))
