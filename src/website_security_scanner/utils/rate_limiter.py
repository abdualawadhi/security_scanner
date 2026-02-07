#!/usr/bin/env python3
"""
Rate limiting utilities for polite, reproducible scanning.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

import requests


@dataclass
class _HostWindow:
    last_request: float
    window_start: float
    count: int


class RateLimiter:
    """
    Simple per-host rate limiter with a minimum interval and max requests per minute.
    """

    def __init__(
        self,
        min_interval_seconds: float = 0.2,
        max_requests_per_minute: Optional[int] = 60,
    ) -> None:
        self.min_interval_seconds = max(0.0, float(min_interval_seconds))
        self.max_requests_per_minute = None
        if max_requests_per_minute is not None:
            max_rpm = int(max_requests_per_minute)
            self.max_requests_per_minute = max_rpm if max_rpm > 0 else None

        self._lock = threading.RLock()
        self._hosts: Dict[str, _HostWindow] = {}

    def wait(self, url: str) -> float:
        """
        Block until a request to the URL is permitted.

        Returns:
            Sleep duration in seconds (0 if no wait).
        """
        host = urlparse(url).netloc.lower() or "global"

        while True:
            with self._lock:
                now = time.time()
                state = self._hosts.get(host)
                if state is None:
                    state = _HostWindow(last_request=0.0, window_start=now, count=0)
                    self._hosts[host] = state

                if now - state.window_start >= 60:
                    state.window_start = now
                    state.count = 0

                wait_for_window = 0.0
                if self.max_requests_per_minute is not None:
                    if state.count >= self.max_requests_per_minute:
                        wait_for_window = max(0.0, state.window_start + 60 - now)

                wait_for_interval = max(
                    0.0, state.last_request + self.min_interval_seconds - now
                )

                wait_for = max(wait_for_window, wait_for_interval)
                if wait_for <= 0:
                    state.last_request = now
                    state.count += 1
                    return 0.0

            time.sleep(wait_for)

    def update_limits(
        self,
        min_interval_seconds: Optional[float] = None,
        max_requests_per_minute: Optional[int] = None,
    ) -> None:
        with self._lock:
            if min_interval_seconds is not None:
                self.min_interval_seconds = max(0.0, float(min_interval_seconds))
            if max_requests_per_minute is not None:
                max_rpm = int(max_requests_per_minute)
                self.max_requests_per_minute = max_rpm if max_rpm > 0 else None


class ThrottledSession(requests.Session):
    """
    Requests session that enforces rate limiting before each request.
    """

    def __init__(self, rate_limiter: RateLimiter):
        super().__init__()
        self._rate_limiter = rate_limiter
        self.default_timeout: Optional[float] = None

    def request(self, method, url, *args, **kwargs):
        if self._rate_limiter:
            self._rate_limiter.wait(url)
        if "timeout" not in kwargs or kwargs.get("timeout") is None:
            if self.default_timeout is not None:
                kwargs["timeout"] = self.default_timeout
        return super().request(method, url, *args, **kwargs)

    def update_rate_limits(
        self,
        min_interval_seconds: Optional[float] = None,
        max_requests_per_minute: Optional[int] = None,
    ) -> None:
        if self._rate_limiter:
            self._rate_limiter.update_limits(
                min_interval_seconds=min_interval_seconds,
                max_requests_per_minute=max_requests_per_minute,
            )
