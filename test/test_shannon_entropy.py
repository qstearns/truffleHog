from truffleHog.truffleHog import (detect_shannon_entropy)


def test_falsey_string():
    false_string = 'Your mom'
    assert (detect_shannon_entropy(false_string) is None)


def test_entropy_af_string():
    random_stringB64 = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
    assert (detect_shannon_entropy(random_stringB64) is True)


def test_entropy_af_hex_string():
    random_stringHex = "b3A0a1FDfe86dcCE945B72"
    assert (detect_shannon_entropy(random_stringHex) is True)
