from sentineldeck.scanners.kev import filter_kev, kev_date


def test_kev_snapshot_loads():
    assert kev_date()  # a non-empty snapshot date


def test_kev_flags_known_exploited():
    # Log4Shell is a canonical CISA KEV entry.
    assert filter_kev(["CVE-2021-44228", "CVE-9999-00001"]) == ["CVE-2021-44228"]


def test_kev_is_case_insensitive():
    assert filter_kev(["cve-2021-44228"]) == ["CVE-2021-44228"]


def test_kev_empty_inputs():
    assert filter_kev([]) == []
    assert filter_kev(["CVE-9999-00002"]) == []
