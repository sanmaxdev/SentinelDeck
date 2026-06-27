from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.cloud_assets import (
    analyze_cloud_assets,
    check_public,
    find_buckets,
)


def test_find_buckets_detects_each_provider():
    text = (
        'img src="https://assets-bucket.s3.amazonaws.com/logo.png" '
        'href="https://storage.googleapis.com/public-data/file.csv" '
        'src="https://media.blob.core.windows.net/x"'
    )

    buckets = {(b["provider"], b["name"]) for b in find_buckets(text)}

    assert ("s3", "assets-bucket") in buckets
    assert ("gcs", "public-data") in buckets
    assert ("azure", "media") in buckets


def test_check_public_reads_listing_xml():
    public = check_public(
        {"provider": "s3", "name": "b", "url": "https://b.s3.amazonaws.com/"},
        fetcher=lambda url, timeout=10: (200, "<ListBucketResult><Contents></Contents></ListBucketResult>"),
    )
    private = check_public(
        {"provider": "s3", "name": "b", "url": "https://b.s3.amazonaws.com/"},
        fetcher=lambda url, timeout=10: (403, ""),
    )

    assert public == "public"
    assert private == "private"


def test_analyze_and_score_public_bucket():
    body = 'src="https://leaky.s3.amazonaws.com/x.js"'
    out = analyze_cloud_assets(
        body,
        fetcher=lambda url, timeout=10: (200, "<ListBucketResult></ListBucketResult>"),
    )

    assert out["buckets"][0]["access"] == "public"

    findings = {f.id: f for f in build_findings({"cloud_assets": out})}
    assert "cloud-bucket-public:leaky" in findings
    assert findings["cloud-bucket-public:leaky"].severity == "high"


def test_private_bucket_is_not_a_finding():
    out = analyze_cloud_assets(
        'src="https://safe.s3.amazonaws.com/x.js"',
        fetcher=lambda url, timeout=10: (403, ""),
    )

    assert "cloud-bucket-public:safe" not in {f.id for f in build_findings({"cloud_assets": out})}
