from shutil import rmtree
from tempfile import mkdtemp

import pytest
from sekoia_automation import constants
from sekoia_automation.storage import get_data_path


@pytest.fixture
def data_storage():
    """Point actions at a fresh temp dir for this test only.

    `sekoia_automation.storage.get_data_path()` is @lru_cache'd, so the FIRST
    test in a session to touch `Action.data_path` permanently caches that
    path — every later test reusing this fixture would silently resolve to a
    directory this test already deleted. Clearing the cache on both sides of
    the swap is required, not optional, once more than one test in the suite
    touches data_path (confirmed by running the full suite: passes file-by-file,
    fails when run together, without this).
    """
    original_storage = constants.DATA_STORAGE
    constants.DATA_STORAGE = mkdtemp()
    get_data_path.cache_clear()

    yield constants.DATA_STORAGE

    rmtree(constants.DATA_STORAGE)
    constants.DATA_STORAGE = original_storage
    get_data_path.cache_clear()
