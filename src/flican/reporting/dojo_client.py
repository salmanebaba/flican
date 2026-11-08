"""Bounded, redirect-free DefectDojo API v2 client."""

import ipaddress
import json
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class DojoAPIError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        return None


class DojoClient:
    def __init__(self, url: str, token: str, timeout: int = 60):
        parsed = urlsplit(url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("The DefectDojo URL must be an origin without embedded credentials.")
        try:
            loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError("DefectDojo requires HTTPS, except for the local loopback instance.")
        if not parsed.hostname or not isinstance(token, str) or not token or any(c in token for c in "\r\n"):
            raise ValueError("Invalid DefectDojo connection.")
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method: str, path: str, data: dict | None = None,
                *, content: bytes | None = None, content_type: str | None = None):
        if not path.startswith("/api/v2/") or "\r" in path or "\n" in path:
            raise ValueError("Invalid DefectDojo API path.")
        if data is not None:
            content = json.dumps(data).encode()
            content_type = "application/json"
        headers = {"Authorization": "Token " + self.token, "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        request = Request(self.url + path, data=content, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(16 * 1024 * 1024 + 1)
        except HTTPError as error:
            error.close()
            raise DojoAPIError(f"DefectDojo returned HTTP {error.code} for {method} {path.split('?')[0]}.", error.code) from None
        except (OSError, URLError) as error:
            raise DojoAPIError("DefectDojo is unavailable; the local scan and pending receipt are retained.") from error
        if len(body) > 16 * 1024 * 1024:
            raise DojoAPIError("DefectDojo response exceeds the size limit.")
        if not body:
            return {}
        try:
            value = json.loads(body)
        except ValueError as error:
            raise DojoAPIError("DefectDojo returned invalid JSON.") from error
        if not isinstance(value, (dict, list)):
            raise DojoAPIError("DefectDojo returned an invalid API response.")
        return value

    def list(self, resource: str, **filters) -> list[dict]:
        path = f"/api/v2/{resource}/?" + urlencode({"limit": 100, **filters})
        result = []
        for _ in range(1000):
            page = self.request("GET", path)
            if not isinstance(page, dict) or not isinstance(page.get("results"), list) or not all(
                isinstance(item, dict) for item in page["results"]
            ):
                raise DojoAPIError("DefectDojo returned an invalid paginated response.")
            result.extend(page["results"])
            next_url = page.get("next")
            if not next_url:
                return result
            if not isinstance(next_url, str):
                raise DojoAPIError("DefectDojo returned an invalid pagination link.")
            parsed = urlsplit(next_url)
            if f"{parsed.scheme}://{parsed.netloc}" != self.url:
                raise DojoAPIError("DefectDojo pagination attempted to change the API origin.")
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
        raise DojoAPIError("DefectDojo pagination exceeds the page limit.")

    def reimport(self, test_id: int, report: dict, *, close_old: bool, completed_at: str):
        boundary = "flican-" + uuid.uuid4().hex
        fields = {
            "test": str(test_id), "scan_type": "Generic Findings Import",
            "minimum_severity": "Info", "close_old_findings": str(close_old).lower(),
            "do_not_reactivate": "false", "deduplication_execution_mode": "sync",
            "scan_date": completed_at[:10],
        }
        parts = []
        for key, value in fields.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="flican.json"\r\nContent-Type: application/json\r\n\r\n'.encode())
        parts.append(json.dumps(report, ensure_ascii=False).encode())
        parts.append(f"\r\n--{boundary}--\r\n".encode())
        payload = b"".join(parts)
        if len(payload) > 32 * 1024 * 1024:
            raise ValueError("The Generic Findings report exceeds the upload limit.")
        return self.request("POST", "/api/v2/reimport-scan/", content=payload,
                            content_type=f"multipart/form-data; boundary={boundary}")
