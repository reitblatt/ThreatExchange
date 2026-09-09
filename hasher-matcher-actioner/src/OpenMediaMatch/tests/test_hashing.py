# Copyright (c) Meta Platforms, Inc. and affiliates.

import io

import pytest
from unittest.mock import Mock, patch
from PIL import Image

from OpenMediaMatch.blueprints.hashing import DEFAULT_MAX_REMOTE_FILE_SIZE, is_valid_url
from OpenMediaMatch.tests.utils import app, client
from threatexchange.signal_type.pdq.signal import PdqSignal
from threatexchange.signal_type.md5 import VideoMD5Signal
from threatexchange.content_type.photo import PhotoContent
from threatexchange.content_type.video import VideoContent


def _jpeg_bytes() -> bytes:
    img = Image.new("RGB", (64, 64))
    pixels = img.load()
    assert pixels is not None
    for x in range(64):
        for y in range(64):
            pixels[x, y] = (255, 255, 255) if (x // 8 + y // 8) % 2 else (0, 0, 0)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def test_valid_urls(app):
    """Test various valid URLs that should pass validation."""
    valid_urls = [
        "https://example.com",
        "https://example.com/path",
        "https://example.com:8080/path",
        "http://example.com",
        "https://sub.example.com",
        "https://example.com/path?query=value",
        "https://example.com/path#fragment",
    ]

    with app.app_context():
        for url in valid_urls:
            assert is_valid_url(url), f"URL should be valid: {url}"


def test_invalid_schemes(app):
    """Test URLs with invalid schemes."""
    invalid_urls = [
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "ws://example.com",
        "wss://example.com",
    ]

    with app.app_context():
        for url in invalid_urls:
            assert not is_valid_url(url), f"URL should be invalid: {url}"


def test_missing_scheme_or_netloc(app):
    """Test URLs missing scheme or netloc."""
    invalid_urls = [
        "example.com",
        "//example.com",
        "http://",
        "https://",
        "",
        None,
    ]

    with app.app_context():
        for url in invalid_urls:
            assert not is_valid_url(url), f"URL should be invalid: {url}"


def test_malformed_urls(app):
    """Test malformed URLs."""
    invalid_urls = [
        "not a url",
        "http://",
        "https://",
        "http:///example.com",
        "http://example.com:",
        "http://example.com:abc",
    ]

    with app.app_context():
        for url in invalid_urls:
            assert not is_valid_url(url), f"URL should be invalid: {url}"


def test_allowed_hostnames(app):
    """Test hostname validation against allowed list."""
    with app.app_context():
        # Set test allowed hostnames
        app.config["ALLOWED_HOSTNAMES"] = {
            "example.com",
            "cdn.example.com",
            "media.example.com",
        }

        # Test allowed hostnames
        for hostname in app.config["ALLOWED_HOSTNAMES"]:
            url = f"https://{hostname}/path"
            assert is_valid_url(url), f"URL should be valid: {url}"

        # Test disallowed hostnames
        invalid_hostnames = [
            "https://evil.com",
            "https://malicious-site.com",
            "https://example.com.evil.com",  # Subdomain attack
            "https://evil.com/example.com",  # Path attack
        ]

        for url in invalid_hostnames:
            assert not is_valid_url(url), f"URL should be invalid: {url}"


def test_empty_allowed_hostnames(app):
    """Test behavior when ALLOWED_HOSTNAMES is empty."""
    with app.app_context():
        # Temporarily set empty allowed hostnames
        app.config["ALLOWED_HOSTNAMES"] = set()

        # All URLs should be allowed when ALLOWED_HOSTNAMES is empty
        test_urls = [
            "https://example.com",
            "https://evil.com",
            "https://any-domain.com",
        ]

        for url in test_urls:
            assert is_valid_url(
                url
            ), f"URL should be valid when ALLOWED_HOSTNAMES is empty: {url}"


@patch("requests.get")
def test_content_length_validation(mock_get, client):
    """Test content length validation."""
    # Mock GET response with large content length
    mock_get_resp = Mock()
    mock_get_resp.headers = {
        "content-type": "image/jpeg",
        "content-length": str(DEFAULT_MAX_REMOTE_FILE_SIZE + 1),
    }
    mock_get_resp.raise_for_status = Mock()
    mock_get.return_value = mock_get_resp

    # Test with large content length
    response = client.get("/h/hash?url=https://example.com/image.jpg")
    assert response.status_code == 413
    assert "Content too large" in response.get_data(as_text=True)

    # Mock GET response with acceptable content length
    mock_get_resp.headers = {
        "content-type": "image/jpeg",
        "content-length": str(DEFAULT_MAX_REMOTE_FILE_SIZE - 1),
    }
    mock_get_resp.iter_content.return_value = [b"fake image data"]

    # Test with acceptable content length
    response = client.get("/h/hash?url=https://example.com/image.jpg")
    assert response.status_code != 413


@patch("requests.get")
def test_content_length_validation_default(mock_get, client, app):
    with app.app_context():
        # Override MAX_REMOTE_FILE_SIZE to None, simulating it not
        # being present in an OMM_CONFIG file:
        app.config["MAX_REMOTE_FILE_SIZE"] = None

        # Mock GET response with large content length
        mock_get_resp = Mock()
        mock_get_resp.headers = {
            "content-type": "image/jpeg",
            "content-length": str(DEFAULT_MAX_REMOTE_FILE_SIZE + 1),
        }
        mock_get_resp.raise_for_status = Mock()
        mock_get.return_value = mock_get_resp

        # Test with large content length
        response = client.get("/h/hash?url=https://example.com/image.jpg")
        assert response.status_code == 413
        assert "Content too large" in response.get_data(as_text=True)


@patch("requests.get")
def test_content_length_validation_misconfiguration(mock_get, client, app):
    with app.app_context():
        # Override MAX_REMOTE_FILE_SIZE to a non-integer value, simulating it
        # being set from the environment variables incorrectly:
        app.config["MAX_REMOTE_FILE_SIZE"] = "not-an-integer"

        mock_get_resp = Mock()
        mock_get_resp.headers = {
            "content-type": "image/jpeg",
            "content-length": str(DEFAULT_MAX_REMOTE_FILE_SIZE + 1),
        }
        mock_get_resp.raise_for_status = Mock()
        mock_get.return_value = mock_get_resp

        # Test with large content length
        response = client.get("/h/hash?url=https://example.com/image.jpg")
        assert response.status_code == 500
        assert "Service misconfigured, see logs for details" in response.get_data(
            as_text=True
        )


def test_hash_post_multipart_upload(client):
    """A multipart/form-data upload under a content-type field name is hashed."""
    image = _jpeg_bytes()
    resp = client.post(
        "/h/hash",
        data={"photo": (io.BytesIO(image), "checker.jpg")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert set(resp.get_json().keys()) == {"pdq"}


def test_hash_post_no_file_is_400(client):
    resp = client.post("/h/hash")
    assert resp.status_code == 400


def test_openapi_documents_multipart_form_data_for_hash_post(client):
    spec = client.get("/openapi/openapi.json").get_json()
    request_body = spec["paths"]["/h/hash"]["post"]["requestBody"]
    assert "multipart/form-data" in request_body["content"]
    ref = request_body["content"]["multipart/form-data"]["schema"]["$ref"]
    assert ref.endswith("/HashPostRequest")
    props = spec["components"]["schemas"]["HashPostRequest"]["properties"]
    assert set(props) == {"photo", "video"}
