from __future__ import annotations

import email.utils
import json
import logging
import random
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class HackuityClient:
    """Client sans fuite de secrets, avec retries réseau et gestion explicite de 429."""

    def __init__(self, config: dict[str, Any], timeout: float = 60, max_attempts: int = 6):
        self.base_url = config["base_url"]
        self.namespace = config["namespace"]
        self.verify_ssl = config["verify_ssl"]
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.api_calls = 0
        self.log = logging.getLogger("hackuity.api")
        if self.verify_ssl is True and sys.platform == "win32":
            try:
                import truststore
                truststore.inject_into_ssl()
                self.log.info("Vérification TLS via le magasin de certificats Windows")
            except ImportError:
                self.log.warning(
                    "truststore absent; utilisation du bundle CA par défaut de requests"
                )
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config['api_key']}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        retry = Retry(total=4, connect=4, read=4, status=0, backoff_factor=1)
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    @staticmethod
    def _safe_payload(value: Any) -> Any:
        sensitive = {"authorization", "api_key", "apikey", "token", "access_token",
                     "password", "secret", "client_secret"}
        if isinstance(value, dict):
            return {key: ("***REDACTED***" if key.lower() in sensitive
                          else HackuityClient._safe_payload(child))
                    for key, child in value.items()}
        if isinstance(value, list):
            return [HackuityClient._safe_payload(child) for child in value]
        return value

    def _log_http_error(self, method: str, path: str, response: requests.Response,
                        kwargs: dict[str, Any]) -> None:
        payload = kwargs.get("json")
        safe_payload = self._safe_payload(payload)
        body = response.text
        if len(body) > 8000:
            body = body[:8000] + "…"
        self.log.error(
            "Erreur HTTP Hackuity\nstatus=%s\nendpoint=%s %s\npayload=%s\nresponse=%s",
            response.status_code, method.upper(), path,
            json.dumps(safe_payload, ensure_ascii=False, default=str),
            body or "<empty>",
        )

    @staticmethod
    def _retry_after(value: str | None, attempt: int) -> float:
        if value:
            try:
                return max(0.0, float(value))
            except ValueError:
                try:
                    parsed = email.utils.parsedate_to_datetime(value)
                    return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
                except (TypeError, ValueError):
                    pass
        return min(60.0, (2 ** attempt) + random.random())

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        for attempt in range(self.max_attempts):
            self.api_calls += 1
            response = self.session.request(
                method, url, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            if response.status_code in {408, 429} or 500 <= response.status_code < 600:
                if attempt + 1 == self.max_attempts:
                    response.raise_for_status()
                delay = self._retry_after(response.headers.get("Retry-After"), attempt)
                self.log.warning("HTTP %s; nouvelle tentative dans %.1fs", response.status_code, delay)
                time.sleep(delay)
                continue
            if not response.ok:
                self._log_http_error(method, path, response, kwargs)
                response.raise_for_status()
            return response.json()
        raise RuntimeError("Nombre maximal de tentatives atteint")

    def finding_detail(self, finding_id: str) -> dict[str, Any]:
        return self.request(
            "GET", f"/api/v1/namespaces/{self.namespace}/findings/{finding_id}",
            params={
                "withActiveProviderInfos": "true", "withSearchInfo": "true",
                "withAssessmentInfos": "true", "withTagsClearValues": "true",
            },
        )
