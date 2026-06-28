from sentineldeck.scanners.archive import archive_history


def test_archive_history_counts_snapshots_and_years():
    rows = [["timestamp"], ["20100101000000"], ["20200101000000"], ["20230101000000"]]
    out = archive_history("e.com", fetcher=lambda d, timeout=10: rows)

    assert out["snapshots"] == 3
    assert out["first"] == "2010"
    assert out["last"] == "2023"


def test_archive_history_empty_when_no_snapshots():
    out = archive_history("e.com", fetcher=lambda d, timeout=10: [["timestamp"]])
    assert out["snapshots"] == 0
    assert out["first"] is None
