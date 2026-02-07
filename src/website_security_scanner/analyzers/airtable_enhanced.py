#!/usr/bin/env python3
"""Airtable analyzer overrides to apply shared web checks."""

from __future__ import annotations

from typing import Any, Dict

import requests
from bs4 import BeautifulSoup

from .airtable import AirtableAnalyzer as BaseAirtableAnalyzer
from .common_web_checks import CommonWebChecksMixin


class AirtableAnalyzer(CommonWebChecksMixin, BaseAirtableAnalyzer):
    """Airtable analyzer that routes shared checks through the common mixin."""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self._current_soup: BeautifulSoup | None = None

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        self._current_soup = soup
        return super().analyze(url, response, soup)

    def _check_secrets_in_javascript(self, js_content: str, url: str):
        return CommonWebChecksMixin._check_secrets_in_javascript(
            self, js_content, url, self._current_soup
        )
