import pytest
@pytest.fixture(autouse=True)
def mock_db():
    yield
