#!/usr/bin/env python3
"""Opt-in downloader for the fixed GUI compatibility baseline installers.

The cache must live outside the repository. Downloads are never attempted
unless ``--allow-network`` is explicitly provided, and every response is
streamed through an allowlisted redirect chain with a bounded byte count and
SHA-256 verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class GuiAsset:
    app_id: str
    display_name: str
    filename: str
    url: str
    sha256: str
    install_args: tuple[str, ...]
    installed_executable: str
    window_title_tokens: tuple[str, ...]


ASSETS = (
    GuiAsset(
        "7zip",
        "7-Zip 26.01",
        "7z2601-x64.exe",
        "https://www.7-zip.org/a/7z2601-x64.exe",
        "d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d",
        ("/S",),
        "Program Files/7-Zip/7zFM.exe",
        ("7-Zip",),
    ),
    GuiAsset(
        "sumatrapdf",
        "SumatraPDF 3.6.1",
        "SumatraPDF-3.6.1-64-install.exe",
        "https://www.sumatrapdfreader.org/dl/rel/3.6.1/SumatraPDF-3.6.1-64-install.exe",
        "1eee71cccd2ea6e94d5bcea54ee2f759844da3e1a0ee2f6045035b1d17b94381",
        ("-silent",),
        "Program Files/SumatraPDF/SumatraPDF.exe",
        ("SumatraPDF",),
    ),
    GuiAsset(
        "notepad-plus-plus",
        "Notepad++ 8.9.6.2",
        "npp.8.9.6.2.Installer.x64.exe",
        "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.6.2/npp.8.9.6.2.Installer.x64.exe",
        "7c243203265ce8fdac76c839bf744ae35dcf620760eb97c2ea279af498560e45",
        ("/S",),
        "Program Files/Notepad++/notepad++.exe",
        ("Notepad++",),
    ),
)

ALLOWED_HOSTS = {
    "www.7-zip.org",
    "7-zip.org",
    "www.sumatrapdfreader.org",
    "sumatrapdfreader.org",
    "files2.sumatrapdfreader.org",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class AssetError(Exception):
    pass


class NetworkUnavailable(AssetError):
    def __init__(self, diagnostic: str) -> None:
        self.diagnostic = diagnostic
        super().__init__("network unavailable")


def asset_for(app_id: str) -> GuiAsset:
    for asset in ASSETS:
        if asset.app_id == app_id:
            return asset
    raise AssetError(f"unknown GUI baseline asset: {app_id}")


def validate_cache_root(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise AssetError("cache-root must be absolute")
    if any(part in (".", "..") for part in path.parts):
        raise AssetError("cache-root must not contain traversal")
    repository = Path(__file__).resolve().parents[1]
    if path == repository or repository in path.parents:
        raise AssetError("cache-root must be outside the repository")
    return path


class AllowlistedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise AssetError("download redirect leaves the official host allowlist")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(asset: GuiAsset, cache_root: Path, allow_network: bool) -> Path:
    destination = cache_root / asset.filename
    if destination.exists():
        if not destination.is_file() or destination.is_symlink():
            raise AssetError("cache entry is not a regular file")
        if digest_file(destination) != asset.sha256:
            raise AssetError(f"cached {asset.app_id} digest mismatch")
        return destination
    if not allow_network:
        raise AssetError(f"{asset.app_id} is not cached; pass --allow-network to download")
    parsed = urllib.parse.urlparse(asset.url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise AssetError("asset URL is outside the official host allowlist")
    cache_root.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{asset.app_id}-", dir=cache_root)
    os.close(descriptor)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    total = 0
    try:
        opener = urllib.request.build_opener(AllowlistedRedirect)
        request = urllib.request.Request(
            asset.url,
            headers={
                "User-Agent": "CompatForge/0.11 (official GUI baseline)",
                "Accept": "application/octet-stream,*/*",
            },
        )
        with opener.open(request, timeout=30) as response, temporary.open("wb") as output:
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise AssetError("download exceeds the bounded asset size")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        actual = digest.hexdigest()
        if actual != asset.sha256:
            raise AssetError(f"downloaded {asset.app_id} digest mismatch")
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary.exists():
            temporary.unlink()


def fetch_classified(asset: GuiAsset, cache_root: Path, allow_network: bool) -> Path:
    try:
        return fetch(asset, cache_root, allow_network)
    except urllib.error.HTTPError:
        # An HTTP response proves the network path is available. Treat a
        # deterministic server/content failure as an asset failure instead.
        raise
    except (urllib.error.URLError, TimeoutError, ConnectionError, socket.gaierror) as error:
        raise NetworkUnavailable(str(error)) from error


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("command", choices=("list", "fetch"))
    value.add_argument("app", nargs="?", choices=tuple(asset.app_id for asset in ASSETS))
    value.add_argument("--cache-root", required=True)
    value.add_argument("--allow-network", action="store_true")
    return value


def asset_json(asset: GuiAsset) -> dict[str, object]:
    return {
        "appId": asset.app_id,
        "displayName": asset.display_name,
        "filename": asset.filename,
        "url": asset.url,
        "sha256": asset.sha256,
        "installArgs": list(asset.install_args),
        "installedExecutable": asset.installed_executable,
        "windowTitleTokens": list(asset.window_title_tokens),
    }


def main() -> int:
    try:
        arguments = parser().parse_args()
        cache_root = validate_cache_root(arguments.cache_root)
        if arguments.command == "list":
            print(json.dumps([asset_json(asset) for asset in ASSETS], ensure_ascii=False, sort_keys=True))
            return 0
        if arguments.app is None:
            raise AssetError("fetch requires an app id")
        path = fetch_classified(asset_for(arguments.app), cache_root, arguments.allow_network)
        print(json.dumps({"appId": arguments.app, "path": str(path)}, ensure_ascii=False, sort_keys=True))
        return 0
    except (AssetError, OSError, urllib.error.URLError, ValueError) as error:
        print(f"compatforge-gui-assets: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
