import pytest
from shadow.config import Paths
from shadow.runtime import Runtime

@pytest.fixture
def paths(tmp_path,monkeypatch):
    monkeypatch.setenv('SHADOW_DATA_DIR',str(tmp_path/'data'))
    monkeypatch.setenv('SHADOW_CONFIG_DIR',str(tmp_path/'config'))
    return Paths()

@pytest.fixture
def runtime(paths):
    state=Runtime(paths)
    yield state
    state.close()
