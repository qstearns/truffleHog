from truffleHog.truffleHog import (detect_shannon_entropy)


def test_falsey_string():
    false_string = 'Your mom'
    assert (detect_shannon_entropy(false_string) == [])


def test_entropy_af_string():
    random_stringB64 = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
    assert (detect_shannon_entropy(random_stringB64)[0].group(0) == random_stringB64)


def test_entropy_af_hex_string():
    random_stringHex = "b3A0a1FDfe86dcCE945B72"
    assert (detect_shannon_entropy(random_stringHex)[0].group(0) == random_stringHex)

def test_double_trouble():
    string = "b3A0a1FDfe86dcCE945B72 ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
    result_strings = [match.group(0) for match in detect_shannon_entropy(string) ]
    assert(set(result_strings) == set(string.split(' ')))

