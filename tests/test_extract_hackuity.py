from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path("scripts").resolve()))
from extract_hackuity import asset_payload, hostname_matches


def test_hostname_does_not_add_unsupported_query_operator() -> None:
    global_payload = asset_payload(0, 500, None, None)
    targeted_payload = asset_payload(0, 500, "BYCVWEB221", None)
    assert targeted_payload == global_payload
    assert "like" not in str(targeted_payload)


def test_global_asset_payload_remains_unchanged() -> None:
    payload = asset_payload(100, 50, None, None)
    assert payload["offset"] == 100
    assert payload["limit"] == 50
    assert payload["searchCriteriaType"] == "QUERY_ENGINE"
    assert payload["query"]["children1"][0]["properties"]["field"] == "asset.state"


def test_short_hostname_matches_fqdn() -> None:
    asset = {"hostname": "bycvweb221.bouygues-construction.com"}
    assert hostname_matches(asset, "BYCVWEB221")


def test_fqdn_requires_exact_normalized_name() -> None:
    asset = {"assetEffectiveName": "BYCVWEB221.bouygues-construction.com."}
    assert hostname_matches(asset, "bycvweb221.bouygues-construction.com")
    assert not hostname_matches(asset, "bycvweb221.other.example")


def test_hostname_filter_does_not_accept_first_unrelated_asset() -> None:
    asset = {"hostname": "unrelated.example"}
    assert not hostname_matches(asset, "BYCVWEB221")
