import io
import json
import urllib.error

import pytest

import handler


class FakeS3:
    """Minimal in-memory stand-in for the boto3 S3 client."""

    class exceptions:
        class NoSuchKey(Exception):
            pass

    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.objects[(Bucket, Key)] = Body

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise self.exceptions.NoSuchKey(Key)
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def keys(self):
        return sorted(key for _, key in self.objects)


def entry(cve, vendor="Acme", product="Widget"):
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "dueDate": "2026-12-01",
        "knownRansomwareCampaignUse": "Unknown",
    }


@pytest.fixture
def s3(monkeypatch):
    fake = FakeS3()
    monkeypatch.setattr(handler, "get_s3", lambda: fake)
    monkeypatch.setenv("BUCKET_NAME", "test-bucket")
    return fake


def run_with_feed(monkeypatch, entries):
    monkeypatch.setattr(handler, "fetch_feed", lambda url: {"vulnerabilities": entries})
    return handler.lambda_handler({}, None)


def test_first_run_records_baseline_without_reporting_new(s3, monkeypatch):
    result = run_with_feed(monkeypatch, [entry("CVE-2026-0001"), entry("CVE-2026-0002")])

    assert result == {"total_entries": 2, "new_entries": 0, "baseline_run": True}
    keys = s3.keys()
    assert "state/seen_cve_ids.json" in keys
    assert any(k.startswith("raw/") and k.endswith("/kev.json") for k in keys)
    assert not any(k.startswith("new/") for k in keys)


def test_second_run_reports_only_new_entries(s3, monkeypatch):
    run_with_feed(monkeypatch, [entry("CVE-2026-0001")])
    result = run_with_feed(monkeypatch, [entry("CVE-2026-0001"), entry("CVE-2026-0002")])

    assert result == {"total_entries": 2, "new_entries": 1, "baseline_run": False}
    new_key = next(k for k in s3.keys() if k.startswith("new/"))
    lines = s3.objects[("test-bucket", new_key)].decode().strip().splitlines()
    assert [json.loads(line)["cveID"] for line in lines] == ["CVE-2026-0002"]


def test_new_entries_are_logged_as_structured_json(s3, monkeypatch, caplog):
    run_with_feed(monkeypatch, [entry("CVE-2026-0001")])
    with caplog.at_level("INFO"):
        run_with_feed(monkeypatch, [entry("CVE-2026-0001"), entry("CVE-2026-0002", "Globex")])

    logged = [json.loads(r.getMessage()) for r in caplog.records]
    new_logs = [m for m in logged if m["event"] == "new_kev_entry"]
    assert len(new_logs) == 1
    assert new_logs[0]["cve"] == "CVE-2026-0002"
    assert new_logs[0]["vendor"] == "Globex"


def test_unchanged_feed_reports_nothing_new(s3, monkeypatch):
    run_with_feed(monkeypatch, [entry("CVE-2026-0001")])
    result = run_with_feed(monkeypatch, [entry("CVE-2026-0001")])
    assert result["new_entries"] == 0
    assert not any(k.startswith("new/") for k in s3.keys())


def test_empty_feed_aborts_without_touching_s3(s3, monkeypatch):
    with pytest.raises(ValueError):
        run_with_feed(monkeypatch, [])
    assert s3.keys() == []


def test_unexpected_s3_errors_are_not_swallowed(s3, monkeypatch):
    def deny(Bucket, Key):
        raise PermissionError("AccessDenied")

    s3.get_object = deny
    with pytest.raises(PermissionError):
        run_with_feed(monkeypatch, [entry("CVE-2026-0001")])


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky_urlopen(request, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("temporary failure")
        return FakeResponse({"vulnerabilities": [entry("CVE-2026-0001")]})

    monkeypatch.setattr(handler.urllib.request, "urlopen", flaky_urlopen)
    monkeypatch.setattr(handler.time, "sleep", lambda s: None)

    feed = handler.fetch_feed("https://example.test/feed.json")
    assert feed["vulnerabilities"][0]["cveID"] == "CVE-2026-0001"
    assert calls["n"] == 3


def test_fetch_gives_up_after_retries(monkeypatch):
    def always_fail(request, timeout):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(handler.urllib.request, "urlopen", always_fail)
    monkeypatch.setattr(handler.time, "sleep", lambda s: None)

    with pytest.raises(RuntimeError):
        handler.fetch_feed("https://example.test/feed.json", retries=2)
