import logging
import sys
from typing import Dict

import pytest

from pip._internal.models.link import Link
from pip._internal.network.download import (
    _get_http_response_filename,
    _prepare_download,
    parse_content_disposition,
    sanitize_content_filename,
)
from tests.lib.requests_mocks import MockResponse


@pytest.mark.parametrize(
    "url, headers, from_cache, expected",
    [
        (
            "http://example.com/foo.tgz",
            {},
            False,
            "Downloading http://example.com/foo.tgz",
        ),
        (
            "http://example.com/foo.tgz",
            {"content-length": "2"},
            False,
            "Downloading http://example.com/foo.tgz (2 bytes)",
        ),
        (
            "http://example.com/foo.tgz",
            {"content-length": "2"},
            True,
            "Using cached http://example.com/foo.tgz (2 bytes)",
        ),
        ("https://files.pythonhosted.org/foo.tgz", {}, False, "Downloading foo.tgz"),
        (
            "https://files.pythonhosted.org/foo.tgz",
            {"content-length": "2"},
            False,
            "Downloading foo.tgz (2 bytes)",
        ),
        (
            "https://files.pythonhosted.org/foo.tgz",
            {"content-length": "2"},
            True,
            "Using cached foo.tgz",
        ),
    ],
)
def test_prepare_download__log(
    caplog: pytest.LogCaptureFixture,
    url: str,
    headers: Dict[str, str],
    from_cache: bool,
    expected: str,
) -> None:
    caplog.set_level(logging.INFO)
    resp = MockResponse(b"")
    resp.url = url
    resp.headers = headers
    if from_cache:
        resp.from_cache = from_cache
    link = Link(url)
    _prepare_download(resp, link, progress_bar="on")

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelname == "INFO"
    assert expected in record.message


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("dir/file", "file"),
        ("../file", "file"),
        ("../../file", "file"),
        ("../", ""),
        ("../..", ".."),
        ("/", ""),
    ],
)
def test_sanitize_content_filename(filename: str, expected: str) -> None:
    """
    Test inputs where the result is the same for Windows and non-Windows.
    """
    assert sanitize_content_filename(filename) == expected


@pytest.mark.parametrize(
    "filename, win_expected, non_win_expected",
    [
        ("dir\\file", "file", "dir\\file"),
        ("..\\file", "file", "..\\file"),
        ("..\\..\\file", "file", "..\\..\\file"),
        ("..\\", "", "..\\"),
        ("..\\..", "..", "..\\.."),
        ("\\", "", "\\"),
    ],
)
def test_sanitize_content_filename__platform_dependent(
    filename: str, win_expected: str, non_win_expected: str
) -> None:
    """
    Test inputs where the result is different for Windows and non-Windows.
    """
    if sys.platform == "win32":
        expected = win_expected
    else:
        expected = non_win_expected
    assert sanitize_content_filename(filename) == expected


@pytest.mark.parametrize(
    "content_disposition, default_filename, expected",
    [
        ('attachment;filename="../file"', "df", "file"),
    ],
)
def test_parse_content_disposition(
    content_disposition: str, default_filename: str, expected: str
) -> None:
    actual = parse_content_disposition(content_disposition, default_filename)
    assert actual == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/simple/x/..%252F..%252F..%252Fevil-1.0-py3-none-any.whl",
        "https://example.com/simple/x/sub%252Fevil-1.0-py3-none-any.whl",
    ],
)
def test_get_http_response_filename_stays_single_component(url: str) -> None:
    # CVE-2026-13346: a doubly-encoded separator in an index URL must not be
    # decoded into a real path separator in the download file name.
    resp = MockResponse(b"")
    resp.url = url
    filename = _get_http_response_filename(resp, Link(url))  # type: ignore[arg-type]
    assert "/" not in filename
    assert filename.endswith("evil-1.0-py3-none-any.whl")


@pytest.mark.parametrize(
    "content_disposition",
    ['attachment;filename=".."', 'attachment;filename="."'],
)
def test_get_http_response_filename_rejects_parent_reference(
    content_disposition: str,
) -> None:
    url = "https://example.com/simple/x/pkg-1.0.tar.gz"
    resp = MockResponse(b"")
    resp.url = url
    resp.headers["content-disposition"] = content_disposition
    with pytest.raises(ValueError):
        _get_http_response_filename(resp, Link(url))  # type: ignore[arg-type]
