from truffleHog import truffleHog
import os
import pytest

def test_shannon():
    random_stringB64 = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
    random_stringHex = "b3A0a1FDfe86dcCE945B72"
    assert (truffleHog.shannon_entropy(random_stringB64, truffleHog.BASE64_CHARS) > 4.5)
    assert (truffleHog.shannon_entropy(random_stringHex, truffleHog.HEX_CHARS) > 3)


def test_cloning():
    project_path = truffleHog.clone_git_repo("https://github.com/dxa4481/truffleHog.git")
    license_file = os.path.join(project_path, "LICENSE")
    assert (os.path.isfile(license_file))


def test_unicode_expection():
    def nop_print(*args):
        pass

    try:
        truffleHog.find_strings("https://github.com/dxa4481/tst.git", nop_print)
    except UnicodeEncodeError:
        pytest.fail("Unicode print error")
