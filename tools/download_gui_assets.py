#!/usr/bin/env python3
"""Opt-in downloader for the fixed GUI compatibility baseline assets.

The cache must live outside the repository. Downloads are never attempted
unless ``--allow-network`` is explicitly provided, and every response is
streamed through an allowlisted redirect chain with a bounded byte count and
SHA-256 verification.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
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

MAX_DOWNLOAD_BYTES = 384 * 1024 * 1024


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
    launch_args: tuple[str, ...] = ()
    install_wait_milliseconds: int = 8_000
    screenshot_delay_seconds: int = 0
    runtime_environment: tuple[tuple[str, str], ...] = ()
    window_appearance_seconds: int = 30
    category: str = "win32"
    toolkit: str = "win32"
    guest_architecture: str = "x86_64"
    alternate_installed_executables: tuple[str, ...] = ()
    package_kind: str = "installer"


BASELINE_ASSETS = (
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
        "SumatraPDF 3.6.1 Portable",
        "SumatraPDF-3.6.1-64.exe",
        "https://www.sumatrapdfreader.org/dl/rel/3.6.1/SumatraPDF-3.6.1-64.exe",
        "719f689b34f47be8ca105ce8484948474dafde0e106bab599e4a89326070c3d0",
        (),
        "CompatForge/SumatraPDF/SumatraPDF.exe",
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

EXTENDED_ASSETS = (
    GuiAsset(
        "firefox",
        "Mozilla Firefox 152.0.1",
        "Firefox_Setup_152.0.1.exe",
        "https://download.mozilla.org/?product=firefox-152.0.1-ssl&os=win64&lang=zh-CN",
        "5435b3117b1789eacb7443259dbea06c6e221cc676d1295b70c190bbac24d72c",
        ("/S",),
        "Program Files/Mozilla Firefox/firefox.exe",
        ("Firefox", "Mozilla"),
        (
            "--no-remote",
            "--new-instance",
            "data:text/html;charset=utf-8,%3Ctitle%3ECompatForge%20Firefox%3C/title%3E%3Ch1%3ECompatForge%20%E4%B8%AD%E6%96%87%E5%85%BC%E5%AE%B9%E9%AA%8C%E8%AF%81%3C/h1%3E",
        ),
        20_000,
        35,
        category="browser",
        toolkit="gecko",
    ),
    GuiAsset(
        "krita",
        "Krita 5.2.9",
        "krita-x64-5.2.9-setup.exe",
        "https://download.kde.org/stable/krita/5.2.9/krita-x64-5.2.9-setup.exe",
        "e394029b3529a7c7411fc200e5627368ac3818a4fda4f453d18c86e220db7057",
        ("/S",),
        "Program Files/Krita (x64)/bin/krita.exe",
        ("Krita",),
        ("--nosplash",),
        45_000,
        30,
        (
            ("WINE_D3D_CONFIG", "renderer=gl,csmt=0x0"),
            ("PYTHONHASHSEED", "0"),
            ("MACWIN_COMPAT_PROFILE", "krita-opengl"),
            ("MACWIN_APP_MODE_INPUT_REPAIR", "1"),
            ("MACWIN_FORCE_MOUSE_FOCUS", "1"),
            ("MACWIN_KRITA_OPENGL_REPAIR", "1"),
            ("QT_ACCESSIBILITY", "0"),
            ("QT_AUTO_SCREEN_SCALE_FACTOR", "0"),
            ("QT_ENABLE_HIGHDPI_SCALING", "0"),
            ("QT_FONT_DPI", "96"),
            ("QT_OPENGL", "desktop"),
            ("QT_SCALE_FACTOR", "1"),
        ),
        55,
        category="graphics",
        toolkit="qt-opengl",
    ),
)

CERTIFICATION_ASSETS = (
    GuiAsset(
        "7zip-x86",
        "7-Zip 26.01 x86",
        "7z2601.exe",
        "https://www.7-zip.org/a/7z2601.exe",
        "615976598f800c70827c5a47e68c2b0d2b17d048b9721ba071c8af825d2476bd",
        ("/S",),
        "Program Files (x86)/7-Zip/7zFM.exe",
        ("7-Zip",),
        guest_architecture="i386",
        alternate_installed_executables=("Program Files/7-Zip/7zFM.exe",),
    ),
    GuiAsset(
        "vlc",
        "VLC media player 3.0.21",
        "vlc-3.0.21-win64.exe",
        "https://ftp.osuosl.org/pub/videolan/vlc/3.0.21/win64/vlc-3.0.21-win64.exe",
        "9742689a50e96ddc04d80ceff046b28da2beefd617be18166f8c5e715ec60c59",
        ("/S",),
        "Program Files/VideoLAN/VLC/vlc.exe",
        ("VLC media player", "VLC"),
        ("--no-qt-privacy-ask", "--no-video-title-show"),
        12_000,
        3,
        category="multimedia",
        toolkit="qt",
    ),
    GuiAsset(
        "winmerge",
        "WinMerge 2.16.58 x64 portable",
        "winmerge-2.16.58-x64-exe.zip",
        "https://github.com/WinMerge/winmerge/releases/download/v2.16.58/winmerge-2.16.58-x64-exe.zip",
        "58a0e36abc99b0da539d3b33b1df8a494239d53900f1ab57c305853df5da94a6",
        (),
        "WinMerge/WinMergeU.exe",
        ("WinMerge",),
        ("/noprefs",),
        window_appearance_seconds=45,
        category="developer-tool",
        toolkit="mfc",
        package_kind="portable-zip",
    ),
    GuiAsset(
        "audacity-x86",
        "Audacity 3.7.8 x86",
        "audacity-win-3.7.8-32bit.exe",
        "https://github.com/audacity/audacity/releases/download/Audacity-3.7.8/audacity-win-3.7.8-32bit.exe",
        "c0482d84a05ddd26905d010daff32b79eba18673489d2cb90ee87a386d24c74f",
        ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"),
        "Program Files (x86)/Audacity/Audacity.exe",
        ("Audacity",),
        install_wait_milliseconds=20_000,
        window_appearance_seconds=45,
        category="audio",
        toolkit="wxwidgets",
        guest_architecture="i386",
        alternate_installed_executables=("Program Files/Audacity/Audacity.exe",),
    ),
    GuiAsset(
        "everything-x86",
        "Everything 1.4.1.1032 x86",
        "Everything-1.4.1.1032.x86-Setup.exe",
        "https://ftp.voidtools.com/Everything-1.4.1.1032.x86-Setup.exe",
        "781a31b440045219752a1bb40fbd204b1d96964d4bf56af01b18e3d549b037aa",
        (
            "/S",
            "-install-options",
            "-app-data -disable-run-as-admin -uninstall-run-on-system-startup -uninstall-service -uninstall-desktop-shortcut -install-start-menu-shortcuts -language 2052",
        ),
        "Program Files (x86)/Everything/Everything.exe",
        ("Everything",),
        ("-nodb",),
        10_000,
        category="search",
        toolkit="win32",
        guest_architecture="i386",
        alternate_installed_executables=("Program Files/Everything/Everything.exe",),
    ),
)

ASSETS = BASELINE_ASSETS + EXTENDED_ASSETS + CERTIFICATION_ASSETS

ALLOWED_HOSTS = {
    "www.7-zip.org",
    "7-zip.org",
    "www.sumatrapdfreader.org",
    "sumatrapdfreader.org",
    "files2.sumatrapdfreader.org",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "download.mozilla.org",
    "download-installer.cdn.mozilla.net",
    "download.kde.org",
    "mirrors.xtom.com",
    "ftp.osuosl.org",
    "ftp.voidtools.com",
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
    except (
        urllib.error.URLError,
        TimeoutError,
        ConnectionError,
        socket.gaierror,
        http.client.HTTPException,
    ) as error:
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
        "launchArgs": list(asset.launch_args),
        "installWaitMilliseconds": asset.install_wait_milliseconds,
        "screenshotDelaySeconds": asset.screenshot_delay_seconds,
        "runtimeEnvironment": dict(asset.runtime_environment),
        "windowAppearanceSeconds": asset.window_appearance_seconds,
        "category": asset.category,
        "toolkit": asset.toolkit,
        "guestArchitecture": asset.guest_architecture,
        "alternateInstalledExecutables": list(asset.alternate_installed_executables),
        "packageKind": asset.package_kind,
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
