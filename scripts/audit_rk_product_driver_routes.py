#!/usr/bin/env python3
"""Inventory official RK keyboard driver selector rows and static web assets.

This scanner reads the dated public-selector and product-package ledgers. With
--fetch-web-assets it downloads only same-origin HTML/JavaScript/CSS linked
from the two official Web driver routes in that snapshot. It never executes
vendor code, follows runtime API calls, or accesses a keyboard. Raw responses
are stored under ignored .research/; only metadata and SHA-256s are written to
docs/.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html.parser
import re
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import HTTPSHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "rk-official-download-selector-catalog-2026-10-19.csv"
PACKAGE_CATALOG = ROOT / "docs" / "rk-product-specific-software-package-catalog-2026-10-19.csv"
ASSET_CSV = ROOT / "docs" / "rk-product-driver-route-web-asset-ledger-2026-10-20.csv"
ROW_CSV = ROOT / "docs" / "rk-product-driver-selector-coverage-2026-10-20.csv"
SYMBOL_CSV = ROOT / "docs" / "rk-product-driver-route-static-symbols-2026-10-20.csv"
RESEARCH_ROOT = ROOT / ".research" / "rk-product-driver-routes-2026-10-20"
WEB_HOSTS = {"drive2.rkgaming.com", "rk.hubx.pro"}
ASSET_SUFFIXES = {".js", ".mjs", ".css"}
JS_REF = re.compile(r"[\"']([^\"']+\.(?:m?js|css)(?:\?[^\"']*)?)[\"']", re.I)
SYMBOLS = [
    ("browser_hid_api", token) for token in ("navigator.hid", "requestDevice", "getDevices", "sendReport", "sendFeatureReport", "receiveFeatureReport", "inputreport")
] + [
    ("browser_transport", token) for token in ("navigator.usb", "navigator.serial", "WebSocket", "XMLHttpRequest", "fetch(", "new Worker", "postMessage")
] + [
    ("feature_or_route_label", token) for token in ("ConnectDrivePage", "DeviceSettingPage", "lighting", "brightness", "backlight", "macro", "keymap", "firmware", "polling", "battery", "knob", "display")
] + [
    ("selector_model_name", token) for token in ("C61", "C68", "C84", "C96", "C98", "F99 AI", "M75 HE", "R99", "RK68 HE", "RK918", "S108")
]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to replace {path}; pass --overwrite intentionally")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class PageReferences(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "script" and values.get("src"):
            self.references.append((values["src"], "html-script"))
        if tag.lower() == "link" and values.get("href"):
            rel = set(values.get("rel", "").lower().split())
            href = values["href"]
            if "stylesheet" in rel:
                self.references.append((href, "html-stylesheet"))
            elif "modulepreload" in rel and Path(urlsplit(href).path).suffix.lower() in {".js", ".mjs"}:
                self.references.append((href, "html-modulepreload"))


def static_refs(base_url: str, content: bytes, kind: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if kind == "html":
        parser = PageReferences()
        parser.feed(content.decode("utf-8", errors="replace"))
        found.extend((urljoin(base_url, value), label) for value, label in parser.references)
    elif kind in {"javascript", "css"}:
        text = content.decode("utf-8", errors="replace")
        for match in JS_REF.finditer(text):
            raw_ref = match.group(1)
            # Vite's __vite__mapDeps stores paths relative to the application
            # root (for example "assets/Chunk.js"), not relative to this
            # entry file under /assets/.
            ref = urljoin(base_url, "/" + raw_ref if raw_ref.startswith("assets/") else raw_ref)
            suffix = Path(urlsplit(ref).path).suffix.lower()
            path = urlsplit(ref).path
            basename = Path(path).name
            host = urlsplit(base_url).hostname
            expected_bundle = path.startswith("/assets/") or (
                host == "rk.hubx.pro"
                and re.match(r"^(?:app|chunk)-[A-Za-z0-9_-]{5,}\.(?:m?js|css)$", basename, re.I)
            )
            if suffix in ASSET_SUFFIXES and expected_bundle:
                found.append((ref, "static-string-reference"))
    return found


def asset_kind(url: str) -> str:
    path = urlsplit(url).path
    if path in {"", "/"}:
        return "html"
    suffix = Path(path).suffix.lower()
    return {".html": "html", ".js": "javascript", ".mjs": "javascript", ".css": "css"}.get(suffix, "other")


def local_path(url: str, route_host: str) -> Path:
    parsed = urlsplit(url)
    path = unquote(parsed.path).lstrip("/") or "index.html"
    parts = [part for part in Path(path).parts if part not in {"", ".", ".."}]
    return RESEARCH_ROOT / route_host / Path(*parts)


def fetch_one(opener, url: str, route_host: str, max_bytes: int, cache: dict[tuple[str, str], dict[str, str]]) -> dict[str, object]:
    request = Request(url, headers={"User-Agent": "RK-Research-Metadata-Audit/1.0", "Accept": "text/html,application/javascript,text/css,*/*;q=0.2"})
    row: dict[str, object] = {
        "route_host": route_host,
        "url": url,
        "final_url": "",
        "http_status": "",
        "content_type": "",
        "byte_length": "",
        "sha256": "",
        "asset_kind": asset_kind(url),
        "acquisition": "",
        "error": "",
        "local_path": "",
    }
    prior = cache.get((route_host, url))
    if prior and prior.get("sha256"):
        path = ROOT / prior.get("local_path", "")
        expected_types = {
            "html": {"text/html", "application/xhtml+xml"},
            "javascript": {"application/javascript", "text/javascript", "application/x-javascript"},
            "css": {"text/css"},
        }.get(str(row["asset_kind"]), set())
        prior_type = str(prior.get("content_type", "")).split(";", 1)[0].strip().lower()
        if path.is_file() and prior_type in expected_types:
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest == prior["sha256"] and len(data) <= max_bytes:
                row.update({
                    "final_url": prior.get("final_url", url),
                    "http_status": prior.get("http_status", "200"),
                    "content_type": prior.get("content_type", ""),
                    "byte_length": len(data),
                    "sha256": digest,
                    "acquisition": "reused_prior_hash_pinned_bytes",
                    "local_path": prior.get("local_path", ""),
                    "tls_validation": prior.get("tls_validation", "prior_run_validation_unknown"),
                })
                return row
    try:
        with opener.open(request, timeout=25) as response:
            final_url = response.geturl()
            row["final_url"] = final_url
            row["http_status"] = response.status
            row["content_type"] = response.headers.get("Content-Type", "")
            if urlsplit(final_url).hostname != route_host:
                row["acquisition"] = "redirect_outside_official_host_not_saved"
                return row
            expected_types = {
                "html": {"text/html", "application/xhtml+xml"},
                "javascript": {"application/javascript", "text/javascript", "application/x-javascript"},
                "css": {"text/css"},
            }.get(str(row["asset_kind"]), set())
            response_type = str(row["content_type"]).split(";", 1)[0].strip().lower()
            if response_type not in expected_types:
                row["acquisition"] = "content_type_mismatch_not_saved"
                return row
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                row["acquisition"] = "response_over_size_limit"
                row["byte_length"] = len(data)
                return row
            path = local_path(url, route_host)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            row["byte_length"] = len(data)
            row["sha256"] = hashlib.sha256(data).hexdigest()
            row["acquisition"] = "acquired_static_bytes"
            row["local_path"] = str(path.relative_to(ROOT))
            return row
    except HTTPError as exc:
        row["http_status"] = exc.code
        row["acquisition"] = "http_error"
        row["error"] = str(exc)
    except (URLError, TimeoutError, OSError) as exc:
        row["acquisition"] = "request_failed"
        row["error"] = str(exc)
    return row


def crawl_route(root_url: str, allow_invalid_tls: bool, max_assets: int, max_bytes: int, max_total_bytes: int, cache: dict[tuple[str, str], dict[str, str]]) -> tuple[list[dict[str, object]], str]:
    route_host = urlsplit(root_url).hostname or ""
    if route_host not in WEB_HOSTS:
        raise ValueError(f"Unexpected web-driver host from catalog: {route_host}")
    invalid_cert_host = route_host == "drive2.rkgaming.com"
    disable_tls_validation = allow_invalid_tls and invalid_cert_host
    context = ssl._create_unverified_context() if disable_tls_validation else ssl.create_default_context()
    opener = build_opener(HTTPSHandler(context=context))
    tls_label = "certificate_verification_disabled_due_to_expired_certificate" if disable_tls_validation else "certificate_validation_enabled"
    queue: list[tuple[str, str]] = [(root_url, "selector-web-route")]
    seen: set[str] = set()
    rows: list[dict[str, object]] = []
    total_bytes = 0
    while queue and len(seen) < max_assets:
        url, discovered_as = queue.pop(0)
        normalized = urlsplit(url)._replace(fragment="").geturl()
        if normalized in seen:
            continue
        seen.add(normalized)
        parsed = urlsplit(normalized)
        if parsed.scheme != "https" or parsed.hostname != route_host:
            rows.append({"route_host": route_host, "url": normalized, "final_url": "", "http_status": "", "content_type": "", "byte_length": "", "sha256": "", "asset_kind": asset_kind(normalized), "acquisition": "external_or_non_https_reference_not_fetched", "error": "", "local_path": "", "discovered_as": discovered_as, "tls_validation": tls_label})
            continue
        if asset_kind(normalized) not in {"html", "javascript", "css"}:
            continue
        row = fetch_one(opener, normalized, route_host, max_bytes, cache)
        row["discovered_as"] = discovered_as
        row["tls_validation"] = tls_label
        rows.append(row)
        if row.get("acquisition") not in {"acquired_static_bytes", "reused_prior_hash_pinned_bytes"}:
            continue
        total_bytes += int(row["byte_length"])
        if total_bytes > max_total_bytes:
            row["acquisition"] = "acquired_but_total_size_limit_reached"
            break
        path = ROOT / str(row["local_path"])
        content = path.read_bytes()
        refs = static_refs(str(row["final_url"]), content, str(row["asset_kind"]))
        for ref_url, ref_kind in refs:
            ref_host = urlsplit(ref_url).hostname
            if ref_host != route_host or urlsplit(ref_url).scheme != "https":
                rows.append({"route_host": route_host, "url": ref_url, "final_url": "", "http_status": "", "content_type": "", "byte_length": "", "sha256": "", "asset_kind": asset_kind(ref_url), "acquisition": "external_or_non_https_reference_not_fetched", "error": "", "local_path": "", "discovered_as": ref_kind, "tls_validation": tls_label})
                continue
            if asset_kind(ref_url) in {"javascript", "css"} and ref_url not in seen:
                queue.append((ref_url, ref_kind))
    if queue:
        rows.append({"route_host": route_host, "url": "", "final_url": "", "http_status": "", "content_type": "", "byte_length": "", "sha256": "", "asset_kind": "", "acquisition": "asset_count_limit_reached", "error": f"max_assets={max_assets}", "local_path": "", "discovered_as": "scanner-limit", "tls_validation": tls_label})
    return rows, tls_label


def package_for(url: str, selector_model: str, packages: list[dict[str, str]]) -> dict[str, str] | None:
    if not url:
        return None
    path = unquote(urlsplit(url).path)
    basename = Path(path).name.lower()
    for row in packages:
        source = row.get("source_url", "")
        if source and source == url:
            return row
    if basename.lower().endswith(".dmg") and selector_model.lower() == "f99 ai":
        return next((row for row in packages if row.get("artifact_kind") == "disk_image" and "f99" in row.get("product", "").lower()), None)
    return next((row for row in packages if row.get("source_url") and Path(urlsplit(row["source_url"]).path).name.lower() == basename), None)


def static_symbol_rows(asset_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    successful = {"acquired_static_bytes", "reused_prior_hash_pinned_bytes"}
    for asset in asset_rows:
        if asset.get("asset_kind") != "javascript" or asset.get("acquisition") not in successful:
            continue
        path = ROOT / str(asset["local_path"])
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != asset.get("sha256"):
            raise ValueError(f"Static asset hash changed after acquisition: {path}")
        for category, token in SYMBOLS:
            pattern = re.compile(re.escape(token.encode("utf-8")), re.IGNORECASE)
            offsets = [match.start() for match in pattern.finditer(data)]
            if offsets:
                rows.append({
                    "route_host": asset.get("route_host", ""),
                    "asset_url": asset.get("url", ""),
                    "asset_sha256": digest,
                    "category": category,
                    "token": token,
                    "occurrence_count": len(offsets),
                    "first_20_byte_offsets": ";".join(str(offset) for offset in offsets[:20]),
                    "interpretation_limit": "lexical occurrence only; not a caller, executed route, feature gate, or device operation",
                })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch-web-assets", action="store_true", help="fetch only same-origin HTML/JS/CSS from catalog Web routes")
    parser.add_argument("--allow-invalid-tls", action="store_true", help="continue static acquisition with TLS certificate validation disabled when upstream cert is expired")
    parser.add_argument("--overwrite", action="store_true", help="replace only the dated metadata CSV outputs")
    parser.add_argument("--max-assets", type=int, default=500)
    parser.add_argument("--max-bytes-per-asset", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=100 * 1024 * 1024)
    args = parser.parse_args()
    if args.allow_invalid_tls and not args.fetch_web_assets:
        parser.error("--allow-invalid-tls is meaningful only with --fetch-web-assets")

    selector_rows = [row for row in read_csv(CATALOG) if row.get("catalog") == "driver"]
    package_rows = read_csv(PACKAGE_CATALOG)
    roots = sorted({row["listed_file_url"] for row in selector_rows if row.get("drive_type") == "Web" and row.get("listed_file_url")})
    asset_rows: list[dict[str, object]] = []
    fetched_hosts: set[str] = set()
    if args.fetch_web_assets:
        cache: dict[tuple[str, str], dict[str, str]] = {}
        if ASSET_CSV.exists():
            for prior in read_csv(ASSET_CSV):
                if prior.get("acquisition") in {"acquired_static_bytes", "reused_prior_hash_pinned_bytes"}:
                    cache[(prior.get("route_host", ""), prior.get("url", ""))] = prior
        for root_url in roots:
            rows, _ = crawl_route(root_url, args.allow_invalid_tls, args.max_assets, args.max_bytes_per_asset, args.max_total_bytes, cache)
            asset_rows.extend(rows)
            if any(r.get("acquisition") in {"acquired_static_bytes", "reused_prior_hash_pinned_bytes"} for r in rows):
                fetched_hosts.add(urlsplit(root_url).hostname or "")

    web_assets_fields = ["route_host", "url", "final_url", "http_status", "content_type", "byte_length", "sha256", "asset_kind", "acquisition", "error", "local_path", "discovered_as", "tls_validation"]
    asset_by_host: dict[str, list[dict[str, object]]] = {}
    for row in asset_rows:
        asset_by_host.setdefault(str(row.get("route_host", "")), []).append(row)

    coverage: list[dict[str, object]] = []
    for row in selector_rows:
        url = row.get("listed_file_url", "")
        host = urlsplit(url).hostname if url else ""
        artifact_hash = ""
        artifact_kind = ""
        artifact_label = ""
        package_record = package_for(url, row.get("selector_model", ""), package_rows)
        if not url:
            status = "no_target_url_listed"
            evidence = "selector row has an empty target URL"
            group = ""
        elif row.get("drive_type") == "Web":
            assets = asset_by_host.get(host or "", [])
            successful = [asset for asset in assets if asset.get("acquisition") in {"acquired_static_bytes", "reused_prior_hash_pinned_bytes"}]
            status = "web_route_static_assets_acquired" if successful else ("web_route_not_fetched" if not args.fetch_web_assets else "web_route_fetch_failed")
            evidence = f"route host {host}; {len(successful)} same-origin HTML/JS/CSS assets acquired" if args.fetch_web_assets else "web application route is selector metadata; no content fetched in this run"
            group = f"web:{host}"
            artifact_kind = "web_application_route"
            artifact_label = host or ""
            if successful and next((asset for asset in successful if asset.get("asset_kind") == "javascript"), None):
                artifact_hash = str(next(asset for asset in successful if asset.get("asset_kind") == "javascript")["sha256"])
        else:
            artifact_label = str((package_record or {}).get("package_label", ""))
            artifact_kind = str((package_record or {}).get("artifact_kind", ""))
            artifact_hash = str((package_record or {}).get("sha256", ""))
            group = f"package:{artifact_label}" if package_record else ""
            if package_record and package_record.get("static_status"):
                status = "prior_official_package_acquired_and_catalogued"
                evidence = f"matching package-catalog record: {package_record.get('static_status')}"
            else:
                status = "listed_package_not_located_in_existing_package_catalog"
                evidence = "nonempty selector URL has no matching row in the dated package catalog"
        coverage.append({
            "selector_model": row.get("selector_model", ""),
            "record_id": row.get("record_id", ""),
            "product_version": row.get("product_version", ""),
            "drive_type": row.get("drive_type", ""),
            "os_route": row.get("os_route", ""),
            "target_url_listed": row.get("target_url_listed", ""),
            "listed_file_url": url,
            "artifact_group": group,
            "artifact_label": artifact_label,
            "artifact_kind": artifact_kind,
            "acquisition_status": status,
            "sha256_from_existing_catalog_or_run": artifact_hash,
            "evidence": evidence,
        })

    row_fields = ["selector_model", "record_id", "product_version", "drive_type", "os_route", "target_url_listed", "listed_file_url", "artifact_group", "artifact_label", "artifact_kind", "acquisition_status", "sha256_from_existing_catalog_or_run", "evidence"]
    write_csv(ROW_CSV, coverage, row_fields, args.overwrite)
    if args.fetch_web_assets:
        write_csv(ASSET_CSV, asset_rows, web_assets_fields, args.overwrite)
        symbol_rows = static_symbol_rows(asset_rows)
        write_csv(SYMBOL_CSV, symbol_rows, ["route_host", "asset_url", "asset_sha256", "category", "token", "occurrence_count", "first_20_byte_offsets", "interpretation_limit"], args.overwrite)
    print(f"driver selector rows: {len(selector_rows)}")
    print(f"distinct listed URLs: {len({r.get('listed_file_url') for r in selector_rows if r.get('listed_file_url')})}")
    print(f"web roots: {len(roots)}")
    print(f"rows: {ROW_CSV.relative_to(ROOT)}")
    if args.fetch_web_assets:
        print(f"web assets: {ASSET_CSV.relative_to(ROOT)}")
        print(f"static token candidates: {SYMBOL_CSV.relative_to(ROOT)} ({len(symbol_rows)} nonempty asset/token pairs)")
        print(f"same-origin assets acquired or hash-verified from previous run: {sum(r.get('acquisition') in {'acquired_static_bytes', 'reused_prior_hash_pinned_bytes'} for r in asset_rows)}")
        for host in sorted(fetched_hosts):
            print(f"fetched host: {host}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
