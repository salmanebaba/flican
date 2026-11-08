"""Keep CLI tests away from the user's persistent Flican journal."""

from tempfile import TemporaryDirectory
from unittest.mock import patch


def isolated_state(testcase):
    directory = testcase.enterContext(TemporaryDirectory(prefix="flican-test-state-"))
    testcase.enterContext(patch.dict("os.environ", {"FLICAN_STATE_DIR": directory}))
