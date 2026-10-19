#!/usr/bin/env python3
"""Capture RK's public keyboard selector metadata without fetching files.

This script reads the public selector page and its JSON catalog endpoints. It
records downloadable URLs as metadata but never requests those URLs. It does
not contact a keyboard, execute a downloaded artifact, or submit device data.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


BASE = "https://en.rkgaming.com"
PAGE = f"{BASE}/download/"
CATEGORY_ID = 1  # Keyboard, as rendered by the official selector page.
DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"

SELECTOR_ENDPOINTS = {
    "driver": "/download/get_version_or_attr_ajax/",
    "firmware": "/firmware/get_firmware_version_or_attr_ajax/",
    "qmk": "/download/get_qmk_version_or_attr_ajax/",
}
RESULT_ENDPOINTS = {
    "driver": "/download/drivers/",
    "firmware": "/firmware/get_firmwares/",
    "qmk": "/download/get_qmk_files/",
}
OS_FIELDS = {
    "Windows": "file",
    "Mac": "mac_file",
    "Linux": "linux_file",
}


class SelectParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.select_id = ""
        self.options: dict[str, list[tuple[str, str]]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "select":
            self.select_id = a.get("id", "") or ""
            self.options.setdefault(self.select_id, [])
        elif tag == "option" and self.select_id:
            self._option_value = a.get("value", "") or ""
            self._option_text = ""

    def handle_data(self, data: str) -> None:
        if self.select_id and hasattr(self, "_option_text"):
            self._option_text += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "option" and self.select_id and hasattr(self, "_option_text"):
            text = re.sub(r"\s+", " ", self._option_text).strip()
            self.options[self.select_id].append((self._option_value, text))
            del self._option_text
            del self._option_value
        elif tag == "select":
            self.select_id = ""


def fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": "RK-public-catalog-audit/1.0"})
    with urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def fetch_json(path: str, params: dict[str, object]) -> tuple[dict, str]:
    url = f"{BASE}{path}?{urlencode(params)}"
    try:
        result = json.loads(fetch_text(url))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Catalog metadata request failed: {url}: {exc}") from exc
    if result.get("code") != 200:
        raise RuntimeError(f"Catalog metadata endpoint returned non-success: {url}: {result!r}")
    return result, url


def all_pages(route: str, model_id: int) -> list[tuple[dict, str]]:
    params: dict[str, object] = {
        "category_id": CATEGORY_ID,
        "version_id": 0,
        "attr_id": 0,
        "product_id": model_id,
        "page": 1,
    }
    first, first_url = fetch_json(route, params)
    page_info = first.get("page", {})
    count = int(page_info.get("total_page", 1))
    pages = [(first, first_url)]
    for page in range(2, count + 1):
        params["page"] = page
        pages.append(fetch_json(route, params))
    return pages


def nonempty(value: object) -> bool:
    return bool(str(value or "").strip())


def normalize_file_url(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith(("https://", "http://", "//")):
        return raw
    if raw.startswith("/"):
        return BASE + raw
    return BASE + "/" + raw


def option_map(items: list[dict]) -> dict[str, str]:
    return {str(item.get("name", "")): str(item.get("id", "")) for item in items}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="CSV output path (default: docs/rk-official-download-selector-catalog-<UTC date>.csv)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing an existing output file; default is to preserve snapshots.",
    )
    args = parser.parse_args()

    observed = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    output = args.output or DOCS_DIR / (
        f"rk-official-download-selector-catalog-{observed[:10]}.csv"
    )
    output = output.resolve()
    if output.exists() and not args.overwrite:
        raise RuntimeError(
            f"Refusing to replace existing snapshot {output}; choose a new --output path "
            "or pass --overwrite to replace it deliberately."
        )

    parser = SelectParser()
    parser.feed(fetch_text(PAGE))
    os_options = [(value, label) for value, label in parser.options.get("os", []) if value]
    language_options = [(value, label) for value, label in parser.options.get("language", []) if value]
    qmk_options = [(value, label) for value, label in parser.options.get("qmk_type", []) if value]
    os_label = {value: label for value, label in os_options}
    language_label = {label: value for value, label in language_options}

    fieldnames = [
        "observed_at_utc", "catalog", "category_id", "selector_model_id", "selector_model",
        "record_id", "record_name", "product_version_id", "product_version", "attribute_id",
        "attribute", "drive_type", "driver_type", "os_route", "target_url_listed",
        "language_id", "language", "qmk_type", "qmk_type_label", "pid", "description",
        "listed_file_url", "metadata_source_url", "source_page_url", "acquisition_status",
    ]
    rows: list[dict[str, str]] = []
    counts: dict[str, dict[str, int]] = {}

    for catalog in ("driver", "firmware", "qmk"):
        selector, selector_url = fetch_json(SELECTOR_ENDPOINTS[catalog], {"category_id": CATEGORY_ID})
        data = selector.get("data", {})
        models = data.get("models", [])
        versions = option_map(data.get("versions", []))
        attrs = option_map(data.get("attrs", []))
        aggregate, _ = fetch_json(RESULT_ENDPOINTS[catalog], {
            "category_id": CATEGORY_ID,
            "version_id": 0,
            "attr_id": 0,
            "page": 1,
        })
        aggregate_count = int(aggregate.get("page", {}).get("count", -1))
        cat_rows = 0
        model_results = 0

        for model in models:
            model_id = int(model["id"])
            for result_page, result_url in all_pages(RESULT_ENDPOINTS[catalog], model_id):
                for item in result_page.get("data", []):
                    model_results += 1
                    product_version = str(item.get("version", ""))
                    attribute = str(item.get("attr", ""))
                    common = {
                        "observed_at_utc": observed,
                        "catalog": catalog,
                        "category_id": str(CATEGORY_ID),
                        "selector_model_id": str(model_id),
                        "selector_model": str(model.get("name", "")),
                        "record_id": str(item.get("id", "")),
                        "record_name": str(item.get("name", "")),
                        "product_version_id": versions.get(product_version, ""),
                        "product_version": product_version,
                        "attribute_id": attrs.get(attribute, ""),
                        "attribute": attribute,
                        "drive_type": str(item.get("drive_type_label", "")),
                        "driver_type": str(item.get("driver_type", "")),
                        "language_id": language_label.get(str(item.get("language", "")), ""),
                        "language": str(item.get("language", "")),
                        "qmk_type": str(item.get("qmk_type", "")),
                        "qmk_type_label": str(item.get("qmk_type_label", "")),
                        "pid": str(item.get("pid", "")),
                        "description": str(item.get("description", "")),
                        "metadata_source_url": result_url,
                        "source_page_url": PAGE,
                        "acquisition_status": "metadata only; listed file URL not fetched",
                    }

                    if catalog == "qmk":
                        file_url = normalize_file_url(item.get("file"))
                        rows.append({**common, "os_route": "not specified by QMK selector",
                                     "target_url_listed": "yes" if file_url else "no",
                                     "listed_file_url": file_url})
                        cat_rows += 1
                    elif catalog == "driver" and (
                        str(item.get("drive_type_label", "")).lower() == "web"
                        or str(item.get("driver_type", "")) == "1"
                    ):
                        file_url = normalize_file_url(item.get("file"))
                        rows.append({**common, "os_route": "web route; platform not specified",
                                     "target_url_listed": "yes" if file_url else "no",
                                     "listed_file_url": file_url})
                        cat_rows += 1
                    else:
                        for os_name, field in OS_FIELDS.items():
                            file_url = normalize_file_url(item.get(field))
                            rows.append({**common, "os_route": os_name,
                                         "target_url_listed": "yes" if file_url else "no",
                                         "listed_file_url": file_url})
                            cat_rows += 1

        if model_results != aggregate_count:
            raise RuntimeError(
                f"Per-model result total {model_results} does not reconcile with "
                f"the aggregate endpoint count {aggregate_count} for {catalog}."
            )
        counts[catalog] = {"models": len(models), "aggregate_result_count": aggregate_count,
                           "model_result_rows": model_results, "catalog_rows": cat_rows}

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(json.dumps({
        "observed_at_utc": observed,
        "source_page": PAGE,
        "selector_api_routes": SELECTOR_ENDPOINTS,
        "result_api_routes": RESULT_ENDPOINTS,
        "os_options": os_options,
        "language_options": language_options,
        "qmk_type_options": qmk_options,
        "counts": counts,
        "rows_written": len(rows),
        "output": str(output),
        "note": "Metadata only. Listed file URLs were not requested or downloaded.",
    }, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, HTTPError, URLError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
