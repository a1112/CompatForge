#!/usr/bin/env python3
"""Validate repository-local contracts without third-party dependencies."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import types
import unicodedata
from pathlib import Path
from pathlib import PurePosixPath

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _VALIDATOR_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _VALIDATOR_CREATE_FILE = _VALIDATOR_KERNEL32.CreateFileW
    _VALIDATOR_CREATE_FILE.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _VALIDATOR_CREATE_FILE.restype = wintypes.HANDLE
    _VALIDATOR_CLOSE_HANDLE = _VALIDATOR_KERNEL32.CloseHandle
    _VALIDATOR_CLOSE_HANDLE.argtypes = (wintypes.HANDLE,)
    _VALIDATOR_CLOSE_HANDLE.restype = wintypes.BOOL
    _VALIDATOR_INVALID_HANDLE = ctypes.c_void_p(-1).value


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_MEMBER = re.compile(r'^\s*"([^"]+)"[,]?\s*$')
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
MIGRATION_CHECK_TIMEOUT_SECONDS = 120
MAX_MIGRATION_CONVERTER_BYTES = 2 * 1024 * 1024
MIGRATION_CONVERTER_BOOTSTRAP = (
    "import sys; path=sys.argv[1]; sys.argv=sys.argv[1:]; "
    "source=sys.stdin.buffer.read(); "
    "namespace={'__file__':path,'__name__':'__main__','__package__':None}; "
    "exec(compile(source,path,'exec'),namespace)"
)
MIGRATION_ENVIRONMENT_NAMES = frozenset(
    {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)
SOURCE_PACK_VALIDATOR = Path(__file__).resolve().parents[1] / "tools" / "import_macwin_source_pack.py"
TASK5_DOCUMENT_PATHS = frozenset(
    {
        "migration/macwin/generated/catalog.json",
        "migration/macwin/generated/quarantine.json",
    }
)
TASK6_DOCUMENT_PATHS = frozenset(
    {
        "migration/macwin/generated/mappings/patches.json",
        "migration/macwin/generated/mappings/bottle-schemas.json",
    }
)
TASK7_DOCUMENT_PATHS = frozenset(
    {"migration/macwin/generated/index.json"}
)
TASK6_EVIDENCE_PATHS = TASK5_DOCUMENT_PATHS | TASK6_DOCUMENT_PATHS
GENERATED_EVIDENCE_PATHS = TASK6_EVIDENCE_PATHS | TASK7_DOCUMENT_PATHS
TASK5_DOCUMENT_SHA256 = {
    "migration/macwin/generated/catalog.json": "c0c5b93b97b3f3c6e9197d2e00645dc28b1163b3130fe3e73ec7d1fde9e8fa4a",
    "migration/macwin/generated/quarantine.json": "ca0132b78ac4bae8ed00446194cd7e9712b37ebc2aea4087ebad695248e2b2e9",
}
TASK6_DOCUMENT_SHA256 = {
    "migration/macwin/generated/mappings/patches.json": "202c56f99c7f332a7b5c6b93b87baef66d1445ae3981954c23f2b6c7ea64edd1",
    "migration/macwin/generated/mappings/bottle-schemas.json": "f99698eaf5e341a58c7f7b91299701481c38df8a31203064aab38822622041cb",
}
TASK7_DOCUMENT_SHA256 = {
    "migration/macwin/generated/index.json": "2c6a0447b4a27c8c0baf0da9dd45cad355db75a6a880e9b90434bc7b93cdf080",
}
PATCH_REVIEW_PATH = "migration/macwin/reviewed/patches.json"
PATCH_REVIEW_DOCUMENT_SHA256 = (
    "38c54730634616bdc0b6a82aa5a5b57bb1c0d6da17d429897cd8da2414bc7783"
)
PATCH_REVIEW_TREE = {"patches.json": "regular"}
MAX_PATCH_REVIEW_BYTES = 1024 * 1024
PATCH_REVIEW_SOURCE = {
    "repository": "a1112/Mac-Win",
    "sourceTag": "mw-migration-baseline-db12d5e",
    "sourceTagObject": "9f10d003382ce7ffbb269376c03477e17516302f",
    "sourceCommit": "db12d5ebc5ba0d5a29c9464d07c1a86ffbc47527",
    "inventoryCommit": "97f8423094d25325d8f864eb6f49a9e8628dbb93",
    "sourceIndexSha256": "1fc8b071a9c52c5f29d130e47e3bd1cb165effa860eaa45336c82ee07cafe3a3",
    "digestAlgorithm": "sha256",
}

# Bottle migration evidence is a deliberately small, public trust root.  The
# validator never asks Rust to produce an expected value; these literal
# digests and projections are checked by a Python standard-library oracle.
BOTTLE_MIGRATION_SCHEMA_SHA256 = {
    "bottle-active-ref.schema.json": "sha256:511fda223f2bde6a271e668ea4faf87835aebeb9a0fb5ab11bab921d7de6d7cb",
    "bottle-migration-plan.schema.json": "sha256:ad2c2eba6031ce04155f4d4b13386318006a23ce6e35885c8808e1ce3c72b562",
    "bottle-runtime-map.schema.json": "sha256:42ce6b2d4bff934e6ed5936aa5f260c17a88ca2c05c671ab01cb4abd8734804c",
    "bottle-snapshot.schema.json": "sha256:6b97f84b1c6740e25e12392e9aa430c2f4d6fb09d7e85c82ffffd2fb1ba8aa97",
}
BOTTLE_MIGRATION_SCHEMA_NAMES = frozenset(
    {
        "bottle.schema.json",
        "application.schema.json",
        "bottle-active-ref.schema.json",
        "bottle-migration-plan.schema.json",
        "bottle-runtime-map.schema.json",
        "bottle-snapshot.schema.json",
        "bottle-executable.schema.json",
        "capability-report.schema.json",
        "compatibility-result.schema.json",
        "context-config.schema.json",
        "executable-inspection.schema.json",
        "guest-artifact.schema.json",
        "launch-plan.schema.json",
        "launch-request.schema.json",
        "job.schema.json",
        "macos-provider.schema.json",
        "macos-bootstrap-request.schema.json",
        "macwin-patch-review.schema.json",
        "macwin-source-pack.schema.json",
        "migration-record.schema.json",
        "portable-fixture.schema.json",
        "portable-probe.schema.json",
        "quarantine.schema.json",
        "recipe.schema.json",
        "runtime-event.schema.json",
        "runtime-pack.schema.json",
        "service-config.schema.json",
        "service-request.schema.json",
        "service-response.schema.json",
        "service-settings.schema.json",
    }
)
BOTTLE_MIGRATION_FILE_SHA256 = {
    "goldens/win32-launch-plan.json": "sha256:041c16b7aa1040395e685db817c2360b57208d8c5d502bec843ee7944845335d",
    "goldens/win32-legacy-planning.json": "sha256:4db891c9b1524fc7cab947e7cb331d42a9a4067e2b53c849e8c8ef600b4fefe7",
    "goldens/win32-migration-plan.json": "sha256:1a7c47bb3491431c9750288e67d85acf8a3d92e854b9afe8646d8a81e044d321",
    "goldens/win64-launch-plan.json": "sha256:e9477955494b6469397a5b1651355b5fd876d7b0814f720243aeee55307373ec",
    "goldens/win64-legacy-planning.json": "sha256:664ed33a9a5743a5d9367c9ac628309fb958e95764630d50c197b126c86bd8b2",
    "goldens/win64-migration-plan.json": "sha256:4be176308c112323f01fe6b21e440d06b2ae828c4d8c2cefb93cc053402a57b4",
    "runtime-map.json": "sha256:c0fedd9cfa46eee8c0f341c744dc82fead8c05b950b9a25bf13454324c664251",
    "win32/drive_c/Public/example.txt": "sha256:bfbf39f393a9f6377038a9a9c84d55712c0ab684bdad24037ec5485cf5cb7303",
    "win32/manifest.json": "sha256:80fd43df02519025556ecf8ba6c679fbcaa61c83e79b2ed090ed91c0528f30f0",
    "win64/drive_c/Public/example.txt": "sha256:bf3e5fba8bf05ea8ac96e264263ac896c31d7d6b4158d32b1aecf3b6d334864e",
    "win64/manifest.json": "sha256:354a64db465bd24939190cab5d3f994ca8a810975ca25c38d1d83ac28ce2e708",
}
BOTTLE_MIGRATION_GOLDEN_SHA256 = {
    relative: digest
    for relative, digest in BOTTLE_MIGRATION_FILE_SHA256.items()
    if relative.startswith("goldens/")
}
BOTTLE_MIGRATION_DIRECTORY_SET = frozenset(
    {
        "goldens",
        "win32",
        "win32/drive_c",
        "win32/drive_c/Public",
        "win64",
        "win64/drive_c",
        "win64/drive_c/Public",
    }
)
BOTTLE_MIGRATION_RUNTIME_PACK_ID = "fixture-runtime"
BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST = (
    "sha256:b7e18e933c0a51f6f1ec387862793e5d22cc2edb7e23c114449ea98357d717af"
)
BOTTLE_MIGRATION_RUNTIME_MAP_DIGEST = (
    "sha256:c0fedd9cfa46eee8c0f341c744dc82fead8c05b950b9a25bf13454324c664251"
)
BOTTLE_MIGRATION_SNAPSHOT_DIGESTS = {
    "win32": "sha256:7a2661322918a821a597d0ccfd1736e8c9f490d6bf41e4f1778c74a121e37523",
    "win64": "sha256:672021ed04ed3e53eff0df940e214bb580bb1690506440867666cd8370288c35",
}
BOTTLE_MIGRATION_PLAN_DIGESTS = {
    "win32": "sha256:0fd681397b014e699a5e1251ee0045e4d1a95408b6cec97791bb2f70805d12da",
    "win64": "sha256:ee984e0e15ba9707b8ff9c6a8ac745c6ecc60149d687ffdda5336cf797388dba",
}
BOTTLE_MIGRATION_CI_RUN_SHA256 = "3c9f1a30ed4956c466cce8a0526d8ae640112abbaf900885af3fd5bef6334300"
BOTTLE_MIGRATION_FIXTURE_COUNTS = {
    "win32": {"entryCount": 4, "totalFileBytes": 558},
    "win64": {"entryCount": 4, "totalFileBytes": 1152},
}
BOTTLE_MIGRATION_MAX_DIRECTORY_ENTRIES = 100_000
BOTTLE_MIGRATION_TRUST_ROOT_MAX_BYTES = 128 * 1024 * 1024
BOTTLE_MIGRATION_DOC_SNIPPETS = {
    "docs/testing.md": (
        "compatforge-cli bottle snapshot",
        "compatforge-cli bottle plan",
        "compatforge-cli bottle import",
        "compatforge-cli bottle verify",
        "compatforge-cli bottle rollback",
        BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST.removeprefix("sha256:"),
    ),
    "docs/migration/work-breakdown.md": (
        "Bottle Bridge",
        "snapshot",
        "rollback",
    ),
    "docs/architecture/component-model.md": (
        "compatforge-bottle",
        "content-addressed",
        "verify-before-switch",
    ),
    "docs/implementation/phase-1-bottle-migration.md": (
        "Source is read-only",
        "Runtime Pack",
        "golden",
        "rollback",
        "| win32 | 4 | 558 |",
        "| win64 | 4 | 1152 |",
        *tuple(digest.removeprefix("sha256:") for digest in BOTTLE_MIGRATION_GOLDEN_SHA256.values()),
    ),
}

# The Bottle boundary is intentionally offline and source-read-only.  These
# are capability names rather than a broad deny-list of filesystem APIs: the
# implementation must still create and atomically publish its private store,
# but it must never grow a network/process/environment/neighbor locator.
BOTTLE_RUNTIME_SOURCE_FILES = (
    "crates/compatforge-bottle/src/platform.rs",
    "crates/compatforge-bottle/src/snapshot.rs",
    "crates/compatforge-bottle/src/store.rs",
)
BOTTLE_RUNTIME_FORBIDDEN_CAPABILITIES = (
    ("macro_rules!", "dynamic capability expansion"),
    # Keep capability imports forbidden as well as concrete calls.  This
    # closes aliases such as ``use std::net as n`` and grouped imports such
    # as ``use std::{process::Command as C}`` without rejecting the allowed
    # ``std::process::id`` used only for unique temporary names.
    ("use std::net", "network access"),
    ("use std::{net", "network access"),
    ("use std {net", "network access"),
    ("use std::os::unix::net", "network access"),
    ("use std::{os::unix::net", "network access"),
    ("use std::os::windows::net", "network access"),
    ("use std::{os::windows::net", "network access"),
    ("use std::process", "subprocess launch"),
    ("use std::{process", "subprocess launch"),
    ("use std {process", "subprocess launch"),
    ("use std::env", "implicit environment access"),
    ("use std::{env", "implicit environment access"),
    ("use std {env", "implicit environment access"),
    ("use std as", "forbidden std capability alias"),
    ("use ::std as", "forbidden std capability alias"),
    ("use {std", "forbidden std capability alias"),
    ("use {::std", "forbidden std capability alias"),
    ("use ::{std", "forbidden std capability alias"),
    ("use std::*", "forbidden std capability alias"),
    ("use ::std::*", "forbidden std capability alias"),
    ("use std::{*", "forbidden std capability alias"),
    ("use ::std::{*", "forbidden std capability alias"),
    ("std::*", "forbidden std capability alias"),
    ("extern crate std as", "forbidden std capability alias"),
    ("extern crate ::std as", "forbidden std capability alias"),
    ("std::net as", "network access"),
    ("std::process as", "subprocess launch"),
    ("std::process::{", "subprocess launch"),
    ("std::process::*", "subprocess launch"),
    ("std::env as", "implicit environment access"),
    ("std::env::{", "implicit environment access"),
    ("std::env::*", "implicit environment access"),
    ("std::os::unix::net as", "network access"),
    ("std::os::unix::{net", "network access"),
    ("std::os::{unix::net", "network access"),
    ("std::os::windows::net as", "network access"),
    ("std::os::windows::{net", "network access"),
    ("std::os::{windows::net", "network access"),
    ("std::{net", "network access"),
    ("std::{process", "subprocess launch"),
    ("std::{env", "implicit environment access"),
    ("std::{self as", "forbidden std capability alias"),
    ("std::{self", "forbidden std capability alias"),
    ("std::net::", "network access"),
    ("std::os::unix::net::", "network access"),
    ("std::os::windows::net::", "network access"),
    ("TcpStream", "network access"),
    ("UnixStream", "network access"),
    ("UdpSocket", "network access"),
    ("ToSocketAddrs", "network access"),
    ("std::process::Command", "subprocess launch"),
    ("std::process::Stdio", "subprocess launch"),
    ("std::env::", "implicit environment access"),
    ("std::env::args", "implicit environment lookup"),
    ("std::env::args_os", "implicit environment lookup"),
    ("std::env::current_exe", "process locator"),
    ("std::env::vars", "implicit environment lookup"),
    ("std::env::vars_os", "implicit environment lookup"),
    ("std::env::var", "implicit environment lookup"),
    ("std::env::var_os", "implicit environment lookup"),
    ("std::env::current_dir", "implicit current-directory lookup"),
    ("std::env::temp_dir", "implicit temporary-directory lookup"),
    ("remove_dir_all", "unbounded recursive cleanup"),
)
BOTTLE_RUNTIME_NEIGHBOR_CALL = re.compile(
    r"(?:std::path::)?Path\s*::\s*new\s*\(\s*['\"](?:\.\.?[/\\])+Mac-Win(?:[/\\]|['\"])",
)
BOTTLE_MIGRATION_CI_SNIPPETS = (
    "tests.test_bottle_migration_contracts",
    "compatforge-bottle",
    "bottle snapshot",
    "bottle plan",
    "bottle import",
    "bottle verify",
    "bottle rollback",
    BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST.removeprefix("sha256:"),
)
PATCH_UPSTREAM_JASP = {
    "repository": "https://github.com/jasp-stats/jasp-desktop",
    "referenceKind": "tag",
    "reference": "v0.97.1",
    "tagObject": None,
    "commit": "28be3fee5c7ce2119f1945acd0254eb4fb8cb6e2",
}
PATCH_UPSTREAM_WINE = {
    "repository": "https://gitlab.winehq.org/wine/wine/",
    "referenceKind": "annotated-tag",
    "reference": "wine-11.11",
    "tagObject": "b08651f36865a3e1d9300d792df322d2ee8a807e",
    "commit": "f6c044e1890e84a4aa5e77e76ba7276a615630e1",
}
PATCH_MISSING_LICENSE_RELEASE = (
    "Record patch-specific license evidence and repeat review."
)
PATCH_PREIMAGE_EVIDENCE_SHA256 = (
    "5d9cc21f82fe883acfa5174d4e06dfdf1cf48ca7ff2e822d8d54fd81bf9d974d"
)
PATCH_PREIMAGE_RECORD_COUNT = 11
PATCH_PREIMAGE_COUNT = 88
PATCH_APPLICATIONS = {
    "patches/jasp-0.97.1-avoid-nested-workspace-reset.patch": (
        "jasp-desktop",
    ),
    "patches/jasp-0.97.1-fix-proxy-model-reset.patch": ("jasp-desktop",),
    "patches/jasp-0.97.1-initialize-enginesync-before-reset.patch": (
        "jasp-desktop",
    ),
    "patches/jasp-0.97.1-local-macos-build-configure.patch": (
        "jasp-build",
        "jasp-desktop",
    ),
    "patches/wine-dcomp-winui-host-composition.patch": ("wine", "winui"),
    "patches/wine-macos-native-ui-integration.patch": ("macos-driver", "wine"),
    "patches/wine-shell32-virtual-desktop-manager.patch": ("shell32", "wine"),
    "patches/wine-windows-data-json-modern-apps.patch": (
        "windows-data-json",
        "wine",
    ),
    "patches/wine-windows-graphics-imaging.patch": (
        "windows-graphics-imaging",
        "wine",
    ),
    "patches/wine-windowscodecs-bilinear-scaler.patch": (
        "windowscodecs",
        "wine",
    ),
    "patches/wine-winui-pointer-input.patch": ("wine", "winui"),
}
PATCH_GIT_OID = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
PATCH_GIT_PREFIX = re.compile(r"^(?!0{7,40}$)[0-9a-f]{7,40}$")
PATCH_ANY_GIT_PREFIX = re.compile(r"^[0-9a-f]{7,40}$")
PATCH_ZERO_GIT_PREFIX = re.compile(r"^0{7,40}$")
PATCH_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PATCH_HTTPS_EVIDENCE = re.compile(
    r"^https://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+"
    r"(?:/|(?:/[A-Za-z0-9._~!$&'()*+,;=:@+-]+)+/?)?$"
)
PATCH_MAIL_AUTHOR = re.compile(r"^([^<>\r\n]{1,256}) <([^<>\s]{3,254})>$")
PATCH_RESERVED_SEGMENT = re.compile(
    r"^(?:conin\$|conout\$|con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$",
    re.IGNORECASE,
)
PATCH_INDEX_LINE = re.compile(
    rb"^index ([0-9a-f]{7,40})\.\.([0-9a-f]{7,40})(?: ([0-7]{6}))?$"
)
TASK5_SOURCE_REPOSITORY = "a1112/Mac-Win"
TASK5_SOURCE_COMMIT = "db12d5ebc5ba0d5a29c9464d07c1a86ffbc47527"
TASK5_CATALOG_ROOT = "MacWinManager/Sources/MacWinManagerApp/Resources/Catalog"
TASK5_CATALOG_INDEX = f"{TASK5_CATALOG_ROOT}/catalog.index.json"
TASK5_CATALOG_SIGNATURE = f"{TASK5_CATALOG_ROOT}/catalog.signature.json"
MAX_TASK5_DOCUMENT_BYTES = 1024 * 1024
MAX_ORDINARY_SCAN_BYTES = 32 * 1024 * 1024
MAX_ORDINARY_SCAN_ENTRIES = 100_000
MAX_ORDINARY_SCAN_TOTAL_BYTES = 1024 * 1024 * 1024
DEVELOPER_PATH_VALIDATION_ERROR = "Repository developer-path validation failed"
MACOS_ACCEPTANCE_REVIEWED_PATHS = (
    "README.md",
    "docs/testing.md",
    "docs/guides/macos-local-dual-runtime-acceptance.md",
    "examples/macos-dual-runtime-interactions.json",
    "tests/test_macos_dual_runtime_acceptance.py",
    "tools/run_macos_dual_runtime_acceptance.py",
)
MACOS_ACCEPTANCE_GUIDE = "docs/guides/macos-local-dual-runtime-acceptance.md"
MACOS_ACCEPTANCE_INTERACTIONS = "examples/macos-dual-runtime-interactions.json"
MACOS_ACCEPTANCE_MAX_MARKDOWN_BYTES = 96 * 1024
MACOS_ACCEPTANCE_MAX_JSON_BYTES = 32 * 1024
MACOS_ACCEPTANCE_RECORDS = (
    ("round-1", "crossover"),
    ("round-1", "whisky"),
    ("round-2", "crossover"),
    ("round-2", "whisky"),
)
MACOS_ACCEPTANCE_INTERACTION_CHECKS = {
    "7zip": frozenset({"fileList", "menus"}),
    "sumatrapdf": frozenset({"mainWindow", "openDialog"}),
    "notepad-plus-plus": frozenset(
        {"open", "edit", "saveUtf8Chinese", "rereadMatches"}
    ),
}
MACOS_ACCEPTANCE_DISCOVERY_COMMAND = (
    "python3 -S -B tools/discover_macos_wine.py --all",
)
MACOS_ACCEPTANCE_PREFLIGHT_COMMANDS = (
    "uname -m",
    "python3 -S -B -c 'import platform,sys; print(sys.executable); print(sys.version); assert sys.version_info >= (3,11); assert platform.machine() == \"arm64\"'",
    "arch -x86_64 /usr/bin/true",
    "test -x /absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc",
    "rustc --version",
    "rustup target list --installed",
    "node --version",
    "npm --version",
    "df -h /absolute/external",
)
MACOS_ACCEPTANCE_ROSETTA_INSTALL_COMMAND = (
    "sudo /usr/sbin/softwareupdate --install-rosetta --agree-to-license",
)
MACOS_ACCEPTANCE_BUILD_COMMANDS = (
    "python3 -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v",
    "python3 -S -B scripts/validate_repository.py",
    "cargo fmt --all -- --check",
    "cargo test --offline --workspace --all-targets --locked",
    "npm ci --offline --prefix apps/desktop",
    "npm run build --prefix apps/desktop",
    "cargo build --offline --release --locked -p compatforge-cli",
    "CARGO_NET_OFFLINE=true npm run tauri --prefix apps/desktop -- build --bundles app",
)
MACOS_ACCEPTANCE_ASSET_LIST_COMMAND = (
    "python3 -S -B tools/download_gui_assets.py list --cache-root /absolute/external/cache",
)
MACOS_ACCEPTANCE_ASSET_FETCH_COMMANDS = (
    "python3 -S -B tools/download_gui_assets.py fetch 7zip --cache-root /absolute/external/cache --allow-network",
    "python3 -S -B tools/download_gui_assets.py fetch sumatrapdf --cache-root /absolute/external/cache --allow-network",
    "python3 -S -B tools/download_gui_assets.py fetch notepad-plus-plus --cache-root /absolute/external/cache --allow-network",
)
MACOS_ACCEPTANCE_ORCHESTRATOR_COMMAND = (
    "python3 -S -B tools/run_macos_dual_runtime_acceptance.py \\",
    "  --compatforge-cli /absolute/external/build/compatforge-cli \\",
    "  --desktop-app /absolute/external/build/CompatForge.app/Contents/MacOS/CompatForge \\",
    "  --cc /absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc \\",
    "  --cache-root /absolute/external/cache \\",
    "  --runtime-store-root /absolute/external/runtime-store \\",
    "  --storage-root /absolute/external/storage \\",
    "  --work-root /absolute/external/evidence \\",
    "  --interaction-evidence-root /absolute/external/interactions",
)
MACOS_ACCEPTANCE_NETWORK_ORCHESTRATOR_COMMAND = (
    "python3 -S -B tools/run_macos_dual_runtime_acceptance.py \\",
    "  --compatforge-cli /absolute/external/build/compatforge-cli \\",
    "  --desktop-app /absolute/external/build/CompatForge.app/Contents/MacOS/CompatForge \\",
    "  --cc /absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc \\",
    "  --cache-root /absolute/external/cache \\",
    "  --runtime-store-root /absolute/external/runtime-store \\",
    "  --storage-root /absolute/external/storage \\",
    "  --work-root /absolute/external/evidence \\",
    "  --interaction-evidence-root /absolute/external/interactions \\",
    "  --allow-network",
)
MACOS_ACCEPTANCE_NEGATIVE_COMMAND = (
    "python3 -S -B tools/run_macos_dual_runtime_acceptance.py \\",
    "  --compatforge-cli /absolute/external/build/compatforge-cli \\",
    "  --desktop-app /absolute/external/build/CompatForge.app/Contents/MacOS/CompatForge \\",
    "  --cc /absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc \\",
    "  --cache-root /absolute/external/cache \\",
    "  --runtime-store-root /absolute/external/negative/runtime-store \\",
    "  --storage-root /absolute/external/negative/storage \\",
    "  --work-root /absolute/external/negative/evidence \\",
    "  --interaction-evidence-root /absolute/external/interactions \\",
    "  --negative-checks \\",
    "  --console-guest /absolute/external/inputs/windows-console-smoke.exe \\",
    "  --negative-sentinel /absolute/external/inputs/negative-sentinel.txt",
)
MACOS_ACCEPTANCE_INTERACTION_PATHS = (
    "/absolute/external/interactions/round-1/crossover.json",
    "/absolute/external/interactions/round-1/whisky.json",
    "/absolute/external/interactions/round-2/crossover.json",
    "/absolute/external/interactions/round-2/whisky.json",
)
MACOS_ACCEPTANCE_GUIDE_BLOCKS = (
    MACOS_ACCEPTANCE_PREFLIGHT_COMMANDS,
    MACOS_ACCEPTANCE_ROSETTA_INSTALL_COMMAND,
    MACOS_ACCEPTANCE_BUILD_COMMANDS,
    MACOS_ACCEPTANCE_DISCOVERY_COMMAND,
    MACOS_ACCEPTANCE_ASSET_LIST_COMMAND,
    MACOS_ACCEPTANCE_ASSET_FETCH_COMMANDS,
    MACOS_ACCEPTANCE_INTERACTION_PATHS,
    MACOS_ACCEPTANCE_ORCHESTRATOR_COMMAND,
    MACOS_ACCEPTANCE_NETWORK_ORCHESTRATOR_COMMAND,
    MACOS_ACCEPTANCE_NEGATIVE_COMMAND,
)
MACOS_ACCEPTANCE_NONCLAIMS = (
    "- `scope`: 本门禁仅为 local-only/developer-local；不是 public beta、public release 或发布门禁。",
    "- `distribution`: 本门禁不签名、不 notarize、不生成或分发 DMG。",
    "- `coverage`: 本门禁不证明所有 Windows 应用、主机或 Runtime 可用。",
    "- `repositories`: 本门禁不修改也不授权修改 ForgeOS、ForgeTools 或 Mac-Win。",
)


def _bind_validator_directory(path: Path) -> tuple[object, tuple[int, int]]:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_reparse_tag", 0)
    ):
        raise ValueError("validator directory is unsafe")
    if os.name == "nt":
        descriptor = _VALIDATOR_CREATE_FILE(
            str(path),
            0x80000000 | 0x0080,
            0x00000001 | 0x00000002,
            None,
            3,
            0x02000000 | 0x00200000,
            None,
        )
        if descriptor == _VALIDATOR_INVALID_HANDLE:
            raise ValueError("validator directory could not be bound")
        opened = metadata
    else:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
    identity = (opened.st_dev, opened.st_ino)
    if not stat.S_ISDIR(opened.st_mode) or identity != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        _close_validator_directory(descriptor)
        raise ValueError("validator directory identity changed")
    return descriptor, identity


def _close_validator_directory(descriptor: object) -> None:
    if os.name == "nt":
        _VALIDATOR_CLOSE_HANDLE(descriptor)
    else:
        os.close(descriptor)


def _read_bound_converter(
    tools: Path, descriptor: object, identity: tuple[int, int]
) -> bytes:
    path = tools / "convert_macwin_assets.py"
    if os.name == "nt":
        raw, _leaf_identity = _read_bound_regular_file(
            path, MAX_MIGRATION_CONVERTER_BYTES
        )
    else:
        leaf = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        try:
            opened = os.fstat(leaf)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size > MAX_MIGRATION_CONVERTER_BYTES
            ):
                raise ValueError("migration converter is unsafe")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(
                    leaf,
                    min(
                        64 * 1024,
                        MAX_MIGRATION_CONVERTER_BYTES + 1 - total,
                    ),
                )
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_MIGRATION_CONVERTER_BYTES:
                    raise ValueError("migration converter is too large")
                chunks.append(chunk)
            final = os.fstat(leaf)
            if _filesystem_identity(final) != _filesystem_identity(opened):
                raise ValueError("migration converter changed")
            raw = b"".join(chunks)
        finally:
            os.close(leaf)
    current = tools.lstat()
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != identity
        or (
            os.name != "nt"
            and (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
            != identity
        )
    ):
        raise ValueError("migration tools binding changed")
    return raw


def validate_macwin_asset_migration() -> list[str]:
    """Run the required migration converter check."""
    converter = ROOT / "tools/convert_macwin_assets.py"
    tools_descriptor: object | None = None
    try:
        tools_descriptor, tools_identity = _bind_validator_directory(
            ROOT / "tools"
        )
        converter_raw = _read_bound_converter(
            ROOT / "tools", tools_descriptor, tools_identity
        )
    except (FileNotFoundError, ValueError):
        return ["Mac-Win asset migration converter path is not a regular file"]
    except OSError:
        return ["Mac-Win asset migration converter path is not a regular file"]
    finally:
        if tools_descriptor is not None:
            _close_validator_directory(tools_descriptor)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in MIGRATION_ENVIRONMENT_NAMES
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                MIGRATION_CONVERTER_BOOTSTRAP,
                str(converter),
                "--check",
            ],
            cwd=ROOT,
            check=False,
            env=environment,
            executable=None,
            input=converter_raw,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=MIGRATION_CHECK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return ["Mac-Win asset migration check timed out"]
    except OSError:
        return ["Mac-Win asset migration check could not start"]
    if completed.returncode == 0:
        return []

    return [f"Mac-Win asset migration check failed with exit {completed.returncode}"]


def validate_json() -> list[str]:
    errors: list[str] = []
    identifiers: dict[str, Path] = {}
    paths = sorted((ROOT / "schemas").glob("*.json"))
    paths += sorted((ROOT / "examples").rglob("*.json"))

    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path.relative_to(ROOT)}: {error}")
            continue

        if "schemaVersion" not in data and path.parent.name != "schemas":
            errors.append(f"{path.relative_to(ROOT)}: missing schemaVersion")

        schema_id = data.get("$id")
        if schema_id:
            if schema_id in identifiers:
                errors.append(
                    f"{path.relative_to(ROOT)}: duplicate $id also used by "
                    f"{identifiers[schema_id].relative_to(ROOT)}"
                )
            identifiers[schema_id] = path

    return errors


def _bottle_reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _bottle_reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _bottle_json(raw: bytes) -> object:
    text = raw.decode("utf-8", errors="strict")
    return json.loads(
        text,
        object_pairs_hook=_bottle_reject_duplicate_keys,
        parse_constant=_bottle_reject_constant,
    )


def _bottle_pretty_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _bottle_compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _bottle_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _bottle_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _bottle_regular_metadata(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
        raise ValueError(f"Bottle migration fixture contains a link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Bottle migration fixture contains a non-regular entry: {path}")
    return metadata


def _bottle_read_regular(path: Path, maximum: int = 2 * 1024 * 1024) -> tuple[bytes, tuple[int, ...]]:
    before = _bottle_regular_metadata(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _bottle_identity(opened) != _bottle_identity(before):
            raise ValueError(f"Bottle migration fixture changed while opening: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError(f"Bottle migration fixture file is too large: {path}")
            chunks.append(chunk)
        after_open = os.fstat(descriptor)
        after_path = _bottle_regular_metadata(path)
        if _bottle_identity(after_open) != _bottle_identity(after_path):
            raise ValueError(f"Bottle migration fixture changed while reading: {path}")
        return b"".join(chunks), _bottle_identity(after_open)
    finally:
        os.close(descriptor)


# The trust-root pass deliberately keeps a private reference to the checked
# reader.  Mutation tests replace ``_bottle_read_regular`` to simulate a
# replacement after one of the semantic passes; the final pass must observe
# the filesystem independently of that test hook.
_BOTTLE_TRUST_READ_REGULAR = _bottle_read_regular


def _bottle_directory_metadata(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
        raise ValueError(f"Bottle migration trust root contains a link: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"Bottle migration trust root is not a directory: {path}")
    return metadata


def _bottle_path_component_is_safe(component: str) -> bool:
    if not component or component in {".", ".."}:
        return False
    if "\\" in component or ":" in component or any(ord(char) < 0x20 for char in component):
        return False
    if component.endswith((".", " ")):
        return False
    if component.casefold().split(".", 1)[0] in {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }:
        return False
    return len(component.encode("utf-8")) <= 255


def _bottle_relative_path_is_safe(relative: str) -> bool:
    if not relative or relative.startswith("/") or "//" in relative:
        return False
    parts = relative.split("/")
    if len(parts) > 128 or len(relative.encode("utf-8")) > 4096:
        return False
    return all(_bottle_path_component_is_safe(part) for part in parts)


def _bottle_walk_fixture(
    root: Path,
    reader=None,
) -> tuple[dict[str, tuple[str, tuple[int, ...], bytes | None]], int, tuple[int, ...]]:
    if reader is None:
        reader = _bottle_read_regular
    identities: dict[str, tuple[str, tuple[int, ...], bytes | None]] = {}
    total_bytes = 0
    root_metadata = root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or getattr(root_metadata, "st_reparse_tag", 0):
        raise ValueError(f"Bottle migration fixture root is a link: {root}")
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"Bottle migration fixture root is not a directory: {root}")
    root_identity = _bottle_identity(root_metadata)
    pending: list[tuple[Path, str, int]] = [(root, "", 0)]
    while pending:
        directory, relative, depth = pending.pop()
        metadata = directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
            raise ValueError(f"Bottle migration fixture contains a link: {directory}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"Bottle migration fixture root is not a directory: {directory}")
        if depth > 128:
            raise ValueError("Bottle migration fixture exceeds path depth")
        try:
            entries = []
            with os.scandir(directory) as scanner:
                for entry in scanner:
                    entries.append(entry)
                    if len(entries) > BOTTLE_MIGRATION_MAX_DIRECTORY_ENTRIES:
                        raise ValueError("Bottle migration fixture directory has too many entries")
            entries.sort(key=lambda entry: entry.name)
        except OSError as error:
            raise ValueError(f"Bottle migration fixture enumeration failed: {error}") from error
        for entry in entries:
            name = entry.name
            child_relative = name if not relative else f"{relative}/{name}"
            if not _bottle_path_component_is_safe(name) or not _bottle_relative_path_is_safe(child_relative):
                raise ValueError(f"Bottle migration fixture has an unsafe path: {child_relative}")
            child = directory / name
            child_metadata = child.lstat()
            identity = _bottle_identity(child_metadata)
            if stat.S_ISLNK(child_metadata.st_mode) or getattr(child_metadata, "st_reparse_tag", 0):
                raise ValueError(f"Bottle migration fixture contains a link: {child_relative}")
            if stat.S_ISDIR(child_metadata.st_mode):
                identities[child_relative] = ("directory", identity, None)
                if len(identities) > 100_000:
                    raise ValueError("Bottle migration fixture has too many entries")
                pending.append((child, child_relative, depth + 1))
                continue
            if not stat.S_ISREG(child_metadata.st_mode):
                raise ValueError(f"Bottle migration fixture contains a non-regular entry: {child_relative}")
            raw, read_identity = reader(child)
            if read_identity != identity:
                raise ValueError(f"Bottle migration fixture changed while reading: {child_relative}")
            total_bytes += len(raw)
            if total_bytes > 64 * 1024 * 1024:
                raise ValueError("Bottle migration fixture exceeds the byte bound")
            identities[child_relative] = ("file", read_identity, raw)
            if len(identities) > 100_000:
                raise ValueError("Bottle migration fixture has too many entries")
    return identities, total_bytes, root_identity


def _bottle_revalidate_fixture(
    root: Path,
    identities: dict[str, tuple[str, tuple[int, ...], bytes | None]],
    root_identity: tuple[int, ...],
) -> None:
    fresh, _, fresh_root_identity = _bottle_walk_fixture(root)
    if fresh_root_identity != root_identity:
        raise ValueError("Bottle migration fixture root changed during validation")
    if set(fresh) != set(identities):
        raise ValueError("Bottle migration fixture changed during validation")
    for relative, (kind, identity, raw) in identities.items():
        current_kind, current_identity, current_raw = fresh[relative]
        if kind != current_kind or identity != current_identity:
            raise ValueError(f"Bottle migration fixture identity changed: {relative}")
        if kind == "file" and raw != current_raw:
            raise ValueError(f"Bottle migration fixture bytes changed: {relative}")


def _bottle_schema_names(schema_root: Path) -> tuple[str, ...]:
    """Return the authenticated Bottle schema names without following links.

    The repository has other (non-Bottle) schemas, so the complete current
    schema set is pinned separately from the four Bottle schema digests.  This
    keeps general schemas available while rejecting arbitrary additions.
    """

    _bottle_directory_metadata(schema_root)
    try:
        entries = []
        with os.scandir(schema_root) as scanner:
            for entry in scanner:
                entries.append(entry)
                if len(entries) > BOTTLE_MIGRATION_MAX_DIRECTORY_ENTRIES:
                    raise ValueError("Bottle schema directory has too many entries")
        entries.sort(key=lambda entry: entry.name)
    except OSError as error:
        raise ValueError(f"Bottle schema directory cannot be enumerated: {error}") from error
    names: list[str] = []
    for entry in entries:
        path = schema_root / entry.name
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
            raise ValueError(f"Bottle schema directory contains a link: {entry.name}")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Bottle schema directory contains a non-regular entry: {entry.name}")
        if not entry.name.endswith(".schema.json"):
            raise ValueError(f"Bottle schema directory contains an unexpected entry: {entry.name}")
        names.append(entry.name)
    if set(names) != BOTTLE_MIGRATION_SCHEMA_NAMES:
        raise ValueError("Bottle schema set drifted")
    return tuple(names)


def _bottle_relative_key(root: Path, path: Path) -> str:
    relative = path.relative_to(root).as_posix()
    return relative or "."


def _bottle_bind_directory_chain(
    root: Path,
    directory: Path,
    identities: dict[str, tuple[int, ...]],
) -> None:
    current = directory
    while True:
        metadata = _bottle_directory_metadata(current)
        identities[_bottle_relative_key(root, current)] = _bottle_identity(metadata)
        if current == root:
            return
        current = current.parent


def _bottle_capture_trust_root(
    root: Path,
) -> tuple[
    dict[str, tuple[int, ...]],
    dict[str, tuple[tuple[int, ...], bytes]],
]:
    """Capture every Bottle validator input with directory and leaf identity."""

    root = root.resolve()
    directories: dict[str, tuple[int, ...]] = {}
    files: dict[str, tuple[tuple[int, ...], bytes]] = {}
    total_bytes = 0

    def capture_file(path: Path, maximum: int = 2 * 1024 * 1024) -> None:
        nonlocal total_bytes
        raw, identity = _BOTTLE_TRUST_READ_REGULAR(path, maximum)
        total_bytes += len(raw)
        if total_bytes > BOTTLE_MIGRATION_TRUST_ROOT_MAX_BYTES:
            raise ValueError("Bottle migration trust root exceeds the byte bound")
        files[_bottle_relative_key(root, path)] = (identity, raw)

    _bottle_bind_directory_chain(root, root, directories)

    fixture_root = root / "tests" / "fixtures" / "bottle-migration"
    fixture_identities, _, fixture_root_identity = _bottle_walk_fixture(
        fixture_root,
        reader=_BOTTLE_TRUST_READ_REGULAR,
    )
    _bottle_bind_directory_chain(root, fixture_root, directories)
    directories[_bottle_relative_key(root, fixture_root)] = fixture_root_identity
    for relative, (kind, identity, raw) in fixture_identities.items():
        path = fixture_root / relative
        key = _bottle_relative_key(root, path)
        if kind == "directory":
            directories[key] = identity
        else:
            if raw is None:
                raise ValueError(f"Bottle fixture file has no bytes: {relative}")
            total_bytes += len(raw)
            if total_bytes > BOTTLE_MIGRATION_TRUST_ROOT_MAX_BYTES:
                raise ValueError("Bottle migration trust root exceeds the byte bound")
            files[key] = (identity, raw)

    schema_root = root / "schemas"
    schema_names = _bottle_schema_names(schema_root)
    _bottle_bind_directory_chain(root, schema_root, directories)
    for name in schema_names:
        path = schema_root / name
        capture_file(path)

    for relative in BOTTLE_MIGRATION_DOC_SNIPPETS:
        path = root / relative
        _bottle_bind_directory_chain(root, path.parent, directories)
        capture_file(path, 2 * 1024 * 1024)
    for relative in ("Cargo.toml", ".github/workflows/ci.yml"):
        path = root / relative
        _bottle_bind_directory_chain(root, path.parent, directories)
        capture_file(path, 2 * 1024 * 1024)
    return directories, files


def _bottle_revalidate_trust_root(
    root: Path,
    expected: tuple[
        dict[str, tuple[int, ...]],
        dict[str, tuple[tuple[int, ...], bytes]],
    ],
) -> None:
    current = _bottle_capture_trust_root(root)
    expected_directories, expected_files = expected
    current_directories, current_files = current
    if current_directories != expected_directories:
        raise ValueError("Bottle migration trust-root directory changed during validation")
    if current_files != expected_files:
        raise ValueError("Bottle migration trust-root bytes or identity changed during validation")


def _bottle_load_document(path: Path, maximum: int = 64 * 1024 * 1024) -> object:
    raw, _ = _bottle_read_regular(path, maximum)
    value = _bottle_json(raw)
    if _bottle_pretty_json(value) != raw:
        raise ValueError(f"Bottle migration document is not canonical: {path}")
    if not isinstance(value, dict):
        raise ValueError(f"Bottle migration document is not an object: {path}")
    return value


def _bottle_require_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has an unexpected field set")
    return value


def _bottle_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _bottle_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a JSON boolean")
    return value


def _bottle_snapshot_projection(case: str, manifest: dict[str, object], root: Path) -> dict[str, object]:
    case_root = root / case
    entries: list[dict[str, object]] = []
    total = 0
    identities, _, _ = _bottle_walk_fixture(case_root)
    for relative in sorted(identities):
        kind, _, raw = identities[relative]
        if kind == "directory":
            entries.append({"kind": "directory", "path": relative})
            continue
        if raw is None:
            raise ValueError(f"Bottle migration fixture file has no bytes: {relative}")
        entries.append(
            {
                "digest": _bottle_digest(raw),
                "kind": "file",
                "path": relative,
                "size": len(raw),
            }
        )
        total += len(raw)
    snapshot = {
        "bottleId": manifest["id"],
        "entries": entries,
        "entryCount": len(entries),
        "legacyFormat": "macwin-bottle-v1",
        "schemaVersion": "1",
        "totalFileBytes": total,
    }
    return {
        "digest": _bottle_digest(
            json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ),
        "entryCount": len(entries),
        "totalFileBytes": total,
    }


def _bottle_legacy_projection(manifest: dict[str, object], runtime_map: dict[str, object]) -> dict[str, object]:
    _bottle_require_keys(
        manifest,
        {
            "id",
            "name",
            "windowsVersion",
            "arch",
            "engineId",
            "envOverrides",
            "installedApps",
            "createdAt",
            "updatedAt",
        },
        "legacy manifest",
    )
    if manifest["arch"] not in {"win32", "win64"}:
        raise ValueError("legacy manifest architecture is unsupported")
    if not isinstance(manifest["envOverrides"], dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in manifest["envOverrides"].items()
    ):
        raise ValueError("legacy Bottle environment is invalid")
    mappings = runtime_map.get("mappings")
    if not isinstance(mappings, list) or len(mappings) != 1:
        raise ValueError("Runtime map must contain exactly one mapping")
    mapping = _bottle_require_keys(
        mappings[0],
        {"legacyEngineId", "runtimePackId", "runtimePackDigest"},
        "Runtime mapping",
    )
    if mapping["legacyEngineId"] != manifest["engineId"]:
        raise ValueError("legacy engine is not mapped")
    if mapping["runtimePackId"] != BOTTLE_MIGRATION_RUNTIME_PACK_ID:
        raise ValueError("Runtime Pack ID drifted")
    if mapping["runtimePackDigest"] != BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST:
        raise ValueError("Runtime Pack digest drifted")
    installed = manifest["installedApps"]
    if not isinstance(installed, list) or not installed:
        raise ValueError("legacy Bottle has no launcher")
    launchers: list[dict[str, object]] = []
    launcher_ids: set[str] = set()
    bottle_id = _bottle_string(manifest["id"], "legacy Bottle ID")
    for launcher in sorted(installed, key=lambda item: item.get("id", "") if isinstance(item, dict) else ""):
        launcher = _bottle_require_keys(
            launcher,
            {
                "id",
                "appId",
                "bottleId",
                "displayName",
                "exePath",
                "args",
                "iconPath",
                "envOverrides",
                "showInHome",
            },
            "legacy launcher",
        )
        launcher_id = _bottle_string(launcher["id"], "launcher ID")
        if launcher_id in launcher_ids:
            raise ValueError("legacy launcher IDs are not unique")
        launcher_ids.add(launcher_id)
        if launcher["bottleId"] != bottle_id:
            raise ValueError("launcher Bottle ID does not match")
        if not isinstance(launcher["args"], list) or not all(isinstance(item, str) for item in launcher["args"]):
            raise ValueError("launcher arguments are invalid")
        if launcher["iconPath"] is not None and not isinstance(launcher["iconPath"], str):
            raise ValueError("launcher icon path is invalid")
        if not isinstance(launcher["envOverrides"], dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in launcher["envOverrides"].items()
        ):
            raise ValueError("launcher environment is invalid")
        _bottle_bool(launcher["showInHome"], "launcher showInHome")
        environment = dict(manifest["envOverrides"])
        environment.update(launcher["envOverrides"])
        output = {
            "id": launcher_id,
            "appId": _bottle_string(launcher["appId"], "launcher app ID"),
            "bottleId": bottle_id,
            "displayName": _bottle_string(launcher["displayName"], "launcher display name"),
            "executable": _bottle_string(launcher["exePath"], "launcher executable"),
            "arguments": launcher["args"],
        }
        if launcher["iconPath"] is not None:
            output["iconPath"] = launcher["iconPath"]
        output["environment"] = [
            {"name": name, "value": value} for name, value in sorted(environment.items())
        ]
        output["showInHome"] = launcher["showInHome"]
        launchers.append(output)
    return {
        "bottleId": bottle_id,
        "name": _bottle_string(manifest["name"], "legacy Bottle name"),
        "windowsVersion": _bottle_string(manifest["windowsVersion"], "Windows version"),
        "architecture": {"win32": "i386", "win64": "x86_64"}[manifest["arch"]],
        "legacyEngineId": _bottle_string(manifest["engineId"], "legacy engine ID"),
        "runtimePack": {
            "id": mapping["runtimePackId"],
            "digest": mapping["runtimePackDigest"],
        },
        "launchers": launchers,
    }


def _bottle_expected_plan(case: str, manifest: dict[str, object], runtime_map: dict[str, object], root: Path) -> dict[str, object]:
    legacy = _bottle_legacy_projection(manifest, runtime_map)
    runtime_pack = legacy["runtimePack"]
    bottle = {
        "schemaVersion": "1",
        "id": manifest["id"],
        "name": manifest["name"],
        "guest": {
            "windowsVersion": manifest["windowsVersion"],
            "architecture": legacy["architecture"],
        },
        "runtimePack": runtime_pack,
        "storage": {"layoutVersion": 1, "state": "ready"},
        "createdAt": manifest["createdAt"],
        "updatedAt": manifest["updatedAt"],
    }
    snapshot = _bottle_snapshot_projection(case, manifest, root)
    expected = {
        "schemaVersion": "1",
        "snapshotDigest": snapshot["digest"],
        "legacyFormat": "macwin-bottle-v1",
        "legacyEngineId": manifest["engineId"],
        "bottle": bottle,
        "bottleDigest": _bottle_digest(_bottle_compact_json(bottle)),
        "runtimePack": runtime_pack,
        "launchers": legacy["launchers"],
        "diagnostics": [],
        "planDigest": "",
    }
    unsigned = dict(expected)
    unsigned.pop("planDigest")
    expected["planDigest"] = _bottle_digest(_bottle_compact_json(unsigned))
    return expected


def _bottle_expected_launch(case: str, manifest: dict[str, object], runtime_map: dict[str, object]) -> dict[str, object]:
    launcher = sorted(manifest["installedApps"], key=lambda item: item["id"])[0]
    environment = dict(manifest["envOverrides"])
    environment.update(launcher["envOverrides"])
    runtime_pack = _bottle_legacy_projection(manifest, runtime_map)["runtimePack"]
    request_ids = {
        "bottle-win64": "018fe3cb-9d12-7b52-b334-1cce0e857fc9",
        "bottle-win32": "018fe3cb-9d12-7b52-b334-1cce0e857fca",
    }
    return {
        "schemaVersion": "1",
        "requestId": request_ids[manifest["id"]],
        "runtime": {"provider": "wine", "packId": runtime_pack["id"], "packDigest": runtime_pack["digest"]},
        "translator": {"provider": "native", "version": "fixture-preview"},
        "graphics": {"backend": "wined3d", "version": "fixture-preview", "options": {}},
        "process": {
            "executable": "/compatforge/runtime/bin/wine",
            "arguments": [launcher["exePath"], *launcher["args"]],
            "environment": environment,
            "workingDirectory": f"/compatforge/bottles/{manifest['id']}/prefix",
        },
        "sandbox": {"profile": "strict", "network": "deny", "allowDevices": []},
        "lifecycle": {"terminationGraceMilliseconds": 3000, "maximumRuntimeMilliseconds": 600000},
        "decisionTrace": [
            "legacy Bottle launcher mapped to verified preview Runtime Pack",
            "environment merge uses launcher override precedence",
        ],
    }


def _bottle_validate_schema_documents(root: Path) -> None:
    schema_root = root / "schemas"
    _bottle_schema_names(schema_root)
    for name, expected_digest in BOTTLE_MIGRATION_SCHEMA_SHA256.items():
        path = schema_root / name
        raw, _ = _bottle_read_regular(path)
        if _bottle_digest(raw) != expected_digest:
            raise ValueError(f"Bottle schema digest drifted: {name}")
        schema = _bottle_json(raw)
        if not isinstance(schema, dict) or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ValueError(f"Bottle schema is not Draft 2020-12: {name}")
        if schema.get("$id") != f"https://compatforge.dev/schemas/{name}":
            raise ValueError(f"Bottle schema ID drifted: {name}")
        if _bottle_pretty_json(schema) != raw:
            raise ValueError(f"Bottle schema is not canonical: {name}")


def _bottle_validate_fixture(root: Path) -> None:
    fixture_root = root / "tests" / "fixtures" / "bottle-migration"
    identities, _, root_identity = _bottle_walk_fixture(fixture_root)
    expected_entries = {
        **{relative: ("file", digest) for relative, digest in BOTTLE_MIGRATION_FILE_SHA256.items()},
        **{relative: ("directory", None) for relative in BOTTLE_MIGRATION_DIRECTORY_SET},
    }
    if set(identities) != set(expected_entries):
        missing = sorted(set(expected_entries) - set(identities))
        extra = sorted(set(identities) - set(expected_entries))
        raise ValueError(f"Bottle fixture tree drifted (missing={missing}, extra={extra})")
    for relative, (kind, expected_digest) in expected_entries.items():
        actual_kind, _, raw = identities[relative]
        if actual_kind != kind:
            raise ValueError(f"Bottle fixture entry kind drifted: {relative}")
        if kind == "file" and _bottle_digest(raw or b"") != expected_digest:
            raise ValueError(f"Bottle fixture digest drifted: {relative}")
    runtime_map = _bottle_load_document(fixture_root / "runtime-map.json")
    _bottle_require_keys(runtime_map, {"schemaVersion", "mappings"}, "Runtime map")
    if runtime_map != {
        "schemaVersion": "1",
        "mappings": [
            {
                "legacyEngineId": "wine-9",
                "runtimePackDigest": BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST,
                "runtimePackId": BOTTLE_MIGRATION_RUNTIME_PACK_ID,
            }
        ],
    }:
        raise ValueError("Runtime map projection drifted")
    for case in ("win32", "win64"):
        manifest = _bottle_load_document(fixture_root / case / "manifest.json")
        legacy = _bottle_legacy_projection(manifest, runtime_map)
        legacy_golden = _bottle_load_document(fixture_root / "goldens" / f"{case}-legacy-planning.json")
        if legacy != legacy_golden:
            raise ValueError(f"Bottle legacy planning golden drifted: {case}")
        plan = _bottle_load_document(fixture_root / "goldens" / f"{case}-migration-plan.json")
        expected_plan = _bottle_expected_plan(case, manifest, runtime_map, fixture_root)
        if plan != expected_plan or plan["planDigest"] != BOTTLE_MIGRATION_PLAN_DIGESTS[case]:
            raise ValueError(f"Bottle migration plan golden drifted: {case}")
        snapshot = _bottle_snapshot_projection(case, manifest, fixture_root)
        if snapshot["digest"] != BOTTLE_MIGRATION_SNAPSHOT_DIGESTS[case]:
            raise ValueError(f"Bottle snapshot digest drifted: {case}")
        if snapshot["entryCount"] != BOTTLE_MIGRATION_FIXTURE_COUNTS[case]["entryCount"] or snapshot["totalFileBytes"] != BOTTLE_MIGRATION_FIXTURE_COUNTS[case]["totalFileBytes"]:
            raise ValueError(f"Bottle snapshot counts drifted: {case}")
        launch = _bottle_load_document(fixture_root / "goldens" / f"{case}-launch-plan.json")
        if launch != _bottle_expected_launch(case, manifest, runtime_map):
            raise ValueError(f"Bottle launch golden drifted: {case}")
    _bottle_revalidate_fixture(fixture_root, identities, root_identity)


def _bottle_visible_markdown(content: str) -> str:
    return re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)


def _bottle_fenced_blocks(content: str) -> list[tuple[str, ...]]:
    blocks: list[tuple[str, ...]] = []
    current: list[str] | None = None
    for line in content.splitlines():
        if line.lstrip().startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append(tuple(current))
                current = None
            continue
        if current is not None:
            current.append(line.rstrip())
    if current is not None:
        raise ValueError("Bottle migration documentation has an unclosed command block")
    return blocks


def _bottle_require_document_commands(relative: str, content: str) -> None:
    commands = {
        "snapshot": re.compile(r"^compatforge-cli bottle snapshot(?:\s|$)"),
        "plan": re.compile(r"^compatforge-cli bottle plan(?:\s|$)"),
        "import": re.compile(r"^compatforge-cli bottle import(?:\s|$)"),
        "verify": re.compile(r"^compatforge-cli bottle verify(?:\s|$)"),
        "rollback": re.compile(r"^compatforge-cli bottle rollback(?:\s|$)"),
    }
    blocks = _bottle_fenced_blocks(content)
    if not any(
        all(any(pattern.match(line) for line in block) for pattern in commands.values())
        for block in blocks
    ):
        raise ValueError(f"Bottle migration documentation command block is incomplete: {relative}")


def _bottle_workspace_members(cargo_text: str) -> set[str]:
    members: set[str] = set()
    in_members = False
    for raw_line in cargo_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not in_members:
            if re.fullmatch(r"members\s*=\s*\[", line):
                in_members = True
            continue
        if line == "]":
            in_members = False
            break
        match = WORKSPACE_MEMBER.fullmatch(line)
        if match:
            members.add(match.group(1))
    if in_members:
        raise ValueError("Bottle migration workspace members array is not closed")
    return members


def _bottle_ci_active_lines(workflow_text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for index, raw_line in enumerate(workflow_text.splitlines()):
        line = raw_line.split("#", 1)[0].rstrip()
        if line.strip():
            lines.append((index, line))
    return lines


def _bottle_require_ci_sequence(workflow_text: str) -> None:
    active = _bottle_ci_active_lines(workflow_text)
    fixture_steps = [
        (position, index, len(line) - len(line.lstrip()))
        for position, (index, line) in enumerate(active)
        if line.strip() == "- name: Run Bottle migration fixture sequence"
    ]
    if len(fixture_steps) != 1:
        raise ValueError("Bottle migration CI fixture step is missing")
    step_position, step_index, step_indent = fixture_steps[0]
    step_lines = []
    for index, line in active[step_position:]:
        if index > step_index and len(line) - len(line.lstrip()) <= step_indent:
            break
        step_lines.append(line)
    run_positions = [index for index, line in enumerate(step_lines) if line.strip() == "run: |"]
    if len(run_positions) != 1:
        raise ValueError("Bottle migration CI fixture step has no run block")
    run_lines = step_lines[run_positions[0] + 1 :]
    canonical_run = ("\n".join(line.strip() for line in run_lines) + "\n").encode("utf-8")
    if hashlib.sha256(canonical_run).hexdigest() != BOTTLE_MIGRATION_CI_RUN_SHA256:
        raise ValueError("Bottle migration CI fixture command block changed")
    stage_positions: list[int] = []
    for stage in ("snapshot", "plan", "import", "verify", "rollback"):
        if stage in {"snapshot", "plan"}:
            command_prefix = r"(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*\"?\$\(\s*)?"
        elif stage == "rollback":
            command_prefix = r"if\s+"
        else:
            command_prefix = ""
        pattern = re.compile(
            rf"^\s*{command_prefix}cargo run -p compatforge-cli --locked -- bottle {stage}(?:\s|$)"
        )
        positions = [index for index, line in enumerate(run_lines) if pattern.search(line)]
        if not positions:
            raise ValueError(f"Bottle migration CI command is missing: {stage}")
        stage_positions.append(positions[0])
    if stage_positions != sorted(stage_positions):
        raise ValueError("Bottle migration CI command sequence is out of order")
    if not any(
        re.search(
            r"^\s*(?:run:\s*)?python(?:3)?\s+.*-m\s+unittest\s+tests\.test_bottle_migration_contracts\b",
            line,
        )
        for _, line in active
    ):
        raise ValueError("Bottle migration CI contract test is missing")
    if not any(
        re.search(r"^\s*(?:run:\s*)?cargo\s+test\s+-p\s+compatforge-bottle\b", line)
        for _, line in active
    ):
        raise ValueError("Bottle migration CI Bottle target is missing")
    runtime_verify = (
        "run: cargo run -p compatforge-cli --locked -- runtime verify "
        f"target/runtime-store {BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST}"
    )
    runtime_step_name = "- name: Verify Runtime Pack fixture v2"
    runtime_steps = [
        (position, len(line) - len(line.lstrip()))
        for position, (_, line) in enumerate(active)
        if line.strip() == runtime_step_name
    ]
    if len(runtime_steps) != 1:
        raise ValueError("Bottle migration CI Runtime Pack verification step is missing")
    runtime_step_position, runtime_step_indent = runtime_steps[0]
    runtime_step_lines: list[str] = []
    for _, line in active[runtime_step_position + 1 :]:
        indent = len(line) - len(line.lstrip())
        if indent <= runtime_step_indent:
            break
        if indent == runtime_step_indent + 2:
            runtime_step_lines.append(line.strip())
    if runtime_step_lines.count(runtime_verify) != 1:
        raise ValueError("Bottle migration CI Runtime Pack verification is missing")

    stripped_run_lines = [line.strip() for line in run_lines]

    def require_adjacent_lines(expected: tuple[str, str], label: str) -> int:
        positions = [
            index
            for index in range(len(stripped_run_lines) - len(expected) + 1)
            if stripped_run_lines[index : index + len(expected)] == list(expected)
        ]
        if len(positions) != 1:
            raise ValueError(f"Bottle migration CI {label} assertion is missing")
        return positions[0]

    snapshot_assertion = require_adjacent_lines(
        (
            'test "$(python -c \'import json,sys; print(json.load(sys.stdin)["snapshotDigest"])\' '
            '<<<"$snapshot_receipt")" = \\',
            f'"{BOTTLE_MIGRATION_SNAPSHOT_DIGESTS["win64"]}"',
        ),
        "snapshot digest",
    )
    plan_assertion = require_adjacent_lines(
        (
            'test "$(python -c \'import json,sys; print(json.load(sys.stdin)["planDigest"])\' '
            '<<<"$plan_receipt")" = \\',
            f'"{BOTTLE_MIGRATION_PLAN_DIGESTS["win64"]}"',
        ),
        "plan digest",
    )
    receipt_assignments = {
        "snapshot": 'snapshot_receipt="$(cargo run -p compatforge-cli --locked -- bottle snapshot \\',
        "plan": 'plan_receipt="$(cargo run -p compatforge-cli --locked -- bottle plan \\',
    }
    for label, assertion_position in (
        ("snapshot", snapshot_assertion),
        ("plan", plan_assertion),
    ):
        assignment_positions = [
            index
            for index, line in enumerate(stripped_run_lines)
            if line == receipt_assignments[label]
        ]
        if len(assignment_positions) != 1 or assignment_positions[0] >= assertion_position:
            raise ValueError(f"Bottle migration CI {label} receipt assignment is missing")


def _bottle_validate_docs_and_ci(root: Path) -> None:
    for relative, snippets in BOTTLE_MIGRATION_DOC_SNIPPETS.items():
        path = root / relative
        raw, _ = _bottle_read_regular(path, 2 * 1024 * 1024)
        content = raw.decode("utf-8", errors="strict")
        visible = _bottle_visible_markdown(content)
        for snippet in snippets:
            if snippet not in visible:
                raise ValueError(f"Bottle migration documentation is incomplete: {relative}")
        if relative in {
            "docs/testing.md",
            "docs/implementation/phase-1-bottle-migration.md",
        }:
            _bottle_require_document_commands(relative, visible)
    cargo, _ = _bottle_read_regular(root / "Cargo.toml", 2 * 1024 * 1024)
    cargo_text = cargo.decode("utf-8", errors="strict")
    members = _bottle_workspace_members(cargo_text)
    if not {"apps/cli", "crates/compatforge-bottle"}.issubset(members):
        raise ValueError("Bottle migration workspace membership is not bound")
    workflow, _ = _bottle_read_regular(root / ".github" / "workflows" / "ci.yml", 2 * 1024 * 1024)
    workflow_text = workflow.decode("utf-8", errors="strict")
    _bottle_require_ci_sequence(workflow_text)


def _bottle_rust_brace_deltas(text: str) -> list[tuple[int, int]]:
    """Return code-brace deltas/counts for each source line.

    The policy scanner only needs enough Rust lexical awareness to skip a
    test-only item safely.  Counting braces in comments or string/raw-string
    literals would let a fixture hide following production code, so those
    tokens are consumed explicitly (including nested block comments).
    """
    mode = "code"
    block_comment_depth = 0
    raw_hashes = 0
    result: list[tuple[int, int]] = []
    for line in text.splitlines(keepends=True):
        delta = 0
        brace_count = 0
        index = 0
        while index < len(line):
            char = line[index]
            if mode == "line-comment":
                if char == "\n":
                    mode = "code"
                index += 1
                continue
            if mode == "block-comment":
                if line.startswith("/*", index):
                    block_comment_depth += 1
                    index += 2
                elif line.startswith("*/", index):
                    block_comment_depth -= 1
                    index += 2
                    if block_comment_depth == 0:
                        mode = "code"
                else:
                    index += 1
                continue
            if mode == "string":
                if char == "\\":
                    index += 2
                else:
                    index += 1
                    if char == '"':
                        mode = "code"
                continue
            if mode == "char":
                if char == "\\":
                    index += 2
                else:
                    index += 1
                    if char == "'":
                        mode = "code"
                continue
            if mode == "raw-string":
                if char == '"':
                    terminator = '"' + ("#" * raw_hashes)
                    if line.startswith(terminator, index):
                        index += len(terminator)
                        mode = "code"
                        continue
                index += 1
                continue

            if line.startswith("//", index):
                mode = "line-comment"
                index += 2
                continue
            if line.startswith("/*", index):
                mode = "block-comment"
                block_comment_depth = 1
                index += 2
                continue

            raw_prefix = 0
            if char == "r":
                raw_prefix = 1
            elif char == "b" and line.startswith("br", index):
                raw_prefix = 2
            if raw_prefix:
                hash_index = index + raw_prefix
                while hash_index < len(line) and line[hash_index] == "#":
                    hash_index += 1
                if hash_index < len(line) and line[hash_index] == '"':
                    raw_hashes = hash_index - index - raw_prefix
                    mode = "raw-string"
                    index = hash_index + 1
                    continue

            if char == '"':
                mode = "string"
                index += 1
                continue
            if char == "'":
                # Do not mistake a Rust lifetime (``'a``) for a character
                # literal.  A literal has a closing quote on this line or an
                # escape/non-identifier as its first payload character.
                next_char = line[index + 1] if index + 1 < len(line) else ""
                closes_short_literal = index + 2 < len(line) and line[index + 2] == "'"
                if next_char in {"\\", "'", "\n", "\r"} or not (next_char.isalnum() or next_char == "_") or closes_short_literal:
                    mode = "char"
                    index += 1
                    continue

            if char in "{}":
                brace_count += 1
                delta += 1 if char == "{" else -1
            index += 1
        result.append((delta, brace_count))
    return result


def _bottle_rust_mask_non_code(text: str) -> str:
    """Blank comments and literals while preserving code/token positions."""
    output = list(text)
    mode = "code"
    block_comment_depth = 0
    raw_hashes = 0

    def blank(index: int) -> None:
        if output[index] not in {"\n", "\r"}:
            output[index] = " "

    index = 0
    while index < len(text):
        char = text[index]
        if mode == "line-comment":
            blank(index)
            if char == "\n":
                mode = "code"
            index += 1
            continue
        if mode == "block-comment":
            blank(index)
            if text.startswith("/*", index):
                blank(index + 1)
                block_comment_depth += 1
                index += 2
            elif text.startswith("*/", index):
                blank(index + 1)
                block_comment_depth -= 1
                index += 2
                if block_comment_depth == 0:
                    mode = "code"
            else:
                index += 1
            continue
        if mode in {"string", "char"}:
            blank(index)
            if char == "\\":
                if index + 1 < len(text):
                    blank(index + 1)
                index += 2
            else:
                index += 1
                if (mode == "string" and char == '"') or (mode == "char" and char == "'"):
                    mode = "code"
            continue
        if mode == "raw-string":
            blank(index)
            terminator = '"' + ("#" * raw_hashes)
            if char == '"' and text.startswith(terminator, index):
                for offset in range(1, len(terminator)):
                    blank(index + offset)
                index += len(terminator)
                mode = "code"
            else:
                index += 1
            continue

        if text.startswith("//", index):
            blank(index)
            blank(index + 1)
            mode = "line-comment"
            index += 2
            continue
        if text.startswith("/*", index):
            blank(index)
            blank(index + 1)
            mode = "block-comment"
            block_comment_depth = 1
            index += 2
            continue

        raw_prefix = 0
        if char == "r":
            raw_prefix = 1
        elif char == "b" and text.startswith("br", index):
            raw_prefix = 2
        if raw_prefix:
            hash_index = index + raw_prefix
            while hash_index < len(text) and text[hash_index] == "#":
                hash_index += 1
            if hash_index < len(text) and text[hash_index] == '"':
                raw_hashes = hash_index - index - raw_prefix
                for offset in range(hash_index - index + 1):
                    blank(index + offset)
                mode = "raw-string"
                index = hash_index + 1
                continue

        if char == '"':
            blank(index)
            mode = "string"
            index += 1
            continue
        if char == "'":
            next_char = text[index + 1] if index + 1 < len(text) else ""
            closes_short_literal = index + 2 < len(text) and text[index + 2] == "'"
            if next_char in {"\\", "'", "\n", "\r"} or not (next_char.isalnum() or next_char == "_") or closes_short_literal:
                blank(index)
                mode = "char"
                index += 1
                continue
        index += 1
    return "".join(output)


def _bottle_cfg_item_has_trailing_tokens(line: str, initial_depth: int = 0) -> bool:
    """Return whether a cfg(test) item shares its line with more code.

    A test-only cfg attribute normally owns the following complete Rust item.
    The scanner must not, however, discard a production item appended after a
    same-line const/function/module/impl.  Use the existing lexical mask so a
    brace or semicolon in a literal cannot manufacture a boundary.  A trailing
    semicolon is allowed for macro items; every other token after the first
    complete top-level item conservatively keeps the whole line in policy
    source.
    """
    masked = _bottle_rust_mask_non_code(line)
    depth = initial_depth
    saw_brace = initial_depth > 0
    index = 0
    while index < len(masked):
        char = masked[index]
        if char == "{":
            saw_brace = True
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if saw_brace and depth == 0:
                trailing = masked[index + 1 :].strip().rstrip(";").strip()
                return bool(trailing)
        elif char == ";" and depth == 0:
            trailing = masked[index + 1 :].strip()
            return bool(trailing)
        index += 1
    return False


def _bottle_test_only_cfg(stripped: str) -> bool:
    """Recognize only cfg expressions that require the test configuration."""
    normalized = "".join(stripped.split())
    return normalized == "#[cfg(test)]" or (
        normalized == "#[cfg(all(test))]"
        or (normalized.startswith("#[cfg(all(test,") and normalized.endswith(")]"))
    )


def _bottle_production_source(text: str) -> str:
    """Remove only provably test-only items before policy scanning.

    Test helpers intentionally use ``temp_dir`` and child-process probes for
    descriptor accounting.  They are not reachable from a release build and
    must not weaken the production boundary scan.  The lexical brace helper
    keeps literals/comments from changing the skipped-item boundary, while
    conservative cfg recognition leaves any expression that is not visibly
    test-required in the production scan.
    """
    kept: list[str] = []
    pending_test_item = False
    skipped_braces = 0
    lines = text.splitlines()
    brace_deltas = _bottle_rust_brace_deltas(text)
    for line, (brace_delta, brace_count) in zip(lines, brace_deltas):
        stripped = line.lstrip()
        if skipped_braces:
            previous_skipped_braces = skipped_braces
            skipped_braces += brace_delta
            if skipped_braces <= 0:
                skipped_braces = 0
                if _bottle_cfg_item_has_trailing_tokens(line, previous_skipped_braces):
                    # The test-only item closed and production code follows on
                    # this line.  Keep the line rather than dropping the
                    # trailing item with the skipped test body.
                    kept.append(line)
            continue
        if pending_test_item:
            if _bottle_cfg_item_has_trailing_tokens(line):
                # A production item follows the cfg(test) item on this line.
                # Keep the complete line: masking comments/literals below
                # remains conservative and avoids trying to split Rust items
                # with a partial parser.
                kept.append(line)
                pending_test_item = False
                skipped_braces = 0
                continue
            if brace_count:
                skipped_braces = brace_delta
                pending_test_item = False
                if skipped_braces <= 0:
                    skipped_braces = 0
                continue
            if ";" in line:
                pending_test_item = False
                continue
            continue
        if stripped.startswith("#[cfg(") and _bottle_test_only_cfg(stripped):
            pending_test_item = True
            continue
        kept.append(line)
    return "\n".join(kept)


def _bottle_validate_runtime_side_effect_policy(root: Path) -> list[str]:
    paths = [root / relative for relative in BOTTLE_RUNTIME_SOURCE_FILES]
    existing = [path for path in paths if path.exists()]
    # Mutation tests and production validation copy the complete implementation
    # boundary.  Older fixture-only validation trees intentionally omit Rust;
    # keep those focused tests independent of the source checkout.
    if not existing:
        return []
    if len(existing) != len(paths):
        return ["Bottle migration runtime source boundary is incomplete"]
    errors: list[str] = []
    for path in paths:
        try:
            source = _bottle_production_source(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            return ["Bottle migration runtime source boundary could not be read"]
        policy_source = _bottle_rust_mask_non_code(source)
        # Rust raw identifiers (``r#process``/``r#env``/etc.) name the same
        # standard modules as their ordinary spellings.  Canonicalize that
        # syntax before matching so it cannot hide an aliased capability.
        normalized_policy_source = re.sub(r"\s+", "", policy_source).replace("r#", "")
        for marker, capability in BOTTLE_RUNTIME_FORBIDDEN_CAPABILITIES:
            normalized_marker = re.sub(r"\s+", "", marker)
            if marker in policy_source or normalized_marker in normalized_policy_source:
                errors.append(
                    f"Bottle migration runtime source uses forbidden {capability}: "
                    f"{path.relative_to(root).as_posix()}"
                )
        for call in re.finditer(r"(?:std::path::)?Path\s*::\s*new", policy_source):
            window = source[call.start() : call.start() + 256]
            if BOTTLE_RUNTIME_NEIGHBOR_CALL.search(window):
                errors.append(
                    "Bottle migration runtime source uses forbidden neighboring "
                    f"Mac-Win checkout access: {path.relative_to(root).as_posix()}"
                )
    return errors


def validate_bottle_migration_repository(root: Path | None = None) -> list[str]:
    """Authenticate the public Bottle migration evidence tree.

    ``root`` is injectable solely for mutation tests.  Production validation
    uses the repository root and performs a final identity/byte revalidation
    after every read, so a replacement race cannot turn an accepted fixture
    into a different artifact.
    """
    repository_root = (root or ROOT).resolve()
    try:
        trust_root = _bottle_capture_trust_root(repository_root)
        _bottle_validate_schema_documents(repository_root)
        _bottle_validate_fixture(repository_root)
        _bottle_validate_docs_and_ci(repository_root)
        side_effect_errors = _bottle_validate_runtime_side_effect_policy(repository_root)
        if side_effect_errors:
            return side_effect_errors
        _bottle_revalidate_trust_root(repository_root, trust_root)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        return [f"Bottle migration repository validation failed: {error}"]
    return []


def validate_workspace_members() -> list[str]:
    errors: list[str] = []
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    in_members = False
    for line in cargo.splitlines():
        if line.strip() == "members = [":
            in_members = True
            continue
        if in_members and line.strip() == "]":
            break
        if not in_members:
            continue
        match = WORKSPACE_MEMBER.match(line)
        if match and not (ROOT / match.group(1) / "Cargo.toml").is_file():
            errors.append(f"workspace member is missing: {match.group(1)}")
    return errors


def validate_markdown_links() -> list[str]:
    errors: list[str] = []
    for path in sorted(ROOT.rglob("*.md")):
        content = path.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK.findall(content):
            target = target.split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            resolved = (path.parent / target).resolve()
            if ROOT not in resolved.parents and resolved != ROOT:
                errors.append(f"{path.relative_to(ROOT)}: link escapes repository: {target}")
            elif not resolved.exists():
                errors.append(f"{path.relative_to(ROOT)}: broken local link: {target}")
    return errors


def _validated_macwin_source_pack_binding() -> tuple[object | None, list[str]]:
    """Return a live identity/content binding for the authenticated source pack."""
    source_root = ROOT / "migration" / "macwin" / "source"
    try:
        source_metadata = source_root.lstat()
    except FileNotFoundError:
        return None, ["Mac-Win source pack validation failed"]
    except OSError:
        return None, ["Mac-Win source pack validation failed"]
    if (
        not stat.S_ISDIR(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or getattr(source_metadata, "st_reparse_tag", 0)
    ):
        return None, ["Mac-Win source pack validation failed"]

    try:
        validator_metadata = SOURCE_PACK_VALIDATOR.lstat()
    except OSError:
        return None, ["Mac-Win source pack validation failed"]
    if (
        not stat.S_ISREG(validator_metadata.st_mode)
        or stat.S_ISLNK(validator_metadata.st_mode)
        or getattr(validator_metadata, "st_reparse_tag", 0)
    ):
        return None, ["Mac-Win source pack validation failed"]

    try:
        spec = importlib.util.spec_from_file_location(
            "repository_macwin_source_pack_validator", SOURCE_PACK_VALIDATOR
        )
        if spec is None or spec.loader is None:
            return None, ["Mac-Win source pack validation failed"]
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(spec.name, None)
        binding = module.bind_source_pack(source_root)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return None, ["Mac-Win source pack validation failed"]
    return binding, []


def _filesystem_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _held_patch_review_leaf_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    identity = _filesystem_identity(metadata)
    return identity[:5]


def _validate_bound_path_chain(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    bindings: list[
        tuple[Path, str, tuple[int, ...]]
    ] = []
    for part in absolute.parts[1:]:
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
            raise ValueError("generated evidence path is linked")
        if stat.S_ISDIR(metadata.st_mode):
            bindings.append((current, "directory", _directory_identity(metadata)))
        elif current == absolute and stat.S_ISREG(metadata.st_mode):
            bindings.append((current, "regular", _filesystem_identity(metadata)))
        else:
            raise ValueError("generated evidence path is invalid")
    for component, kind, identity in bindings:
        metadata = component.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
            raise ValueError("generated evidence path identity changed")
        if kind == "directory":
            valid = stat.S_ISDIR(metadata.st_mode) and _directory_identity(
                metadata
            ) == identity
        else:
            valid = stat.S_ISREG(metadata.st_mode) and _filesystem_identity(
                metadata
            ) == identity
        if not valid:
            raise ValueError("generated evidence path identity changed")


def _read_bound_regular_file(
    path: Path,
    maximum: int,
    *,
    require_single_link: bool = True,
) -> tuple[bytes, tuple[int, int, int, int, int, int]]:
    if type(require_single_link) is not bool:
        raise TypeError("regular-file link policy is invalid")
    _validate_bound_path_chain(path)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or getattr(before, "st_reparse_tag", 0)
        or (require_single_link and before.st_nlink != 1)
        or before.st_size > maximum
    ):
        raise ValueError("generated evidence leaf is invalid")
    identity = _filesystem_identity(before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _filesystem_identity(opened)[:4] != identity[:4]:
            raise ValueError("generated evidence identity changed")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError("generated evidence exceeds the byte limit")
            chunks.append(chunk)
        final = os.fstat(descriptor)
        if _filesystem_identity(final) != _filesystem_identity(opened):
            raise ValueError("generated evidence identity changed")
    finally:
        os.close(descriptor)
    after = path.lstat()
    if _filesystem_identity(after) != identity:
        raise ValueError("generated evidence identity changed")
    _validate_bound_path_chain(path)
    return b"".join(chunks), identity


class _GeneratedEvidenceBinding:
    """Bind the exact Task 7 generated graph to converter-rebuilt bytes."""

    def __init__(
        self,
        generated_root: Path,
        root_identity: tuple[int, int, int, int, int, int],
        expected: dict[str, bytes],
        leaves: dict[Path, tuple[bytes, tuple[int, int, int, int, int, int]]],
        directories: dict[
            Path,
            tuple[tuple[int, int], tuple[tuple[str, str], ...]],
        ],
        converter: object,
        converter_path: Path,
        converter_raw: bytes,
        converter_identity: tuple[int, int, int, int, int, int],
        patch_review_binding: _PatchReviewBinding,
    ) -> None:
        self.generated_root = generated_root
        self.root_identity = root_identity
        self.expected = expected
        self.leaves = leaves
        self.directories = directories
        self.converter = converter
        self.converter_path = converter_path
        self.converter_raw = converter_raw
        self.converter_identity = converter_identity
        self.patch_review_binding = patch_review_binding

    def contains(self, path: Path) -> bool:
        return path.absolute() in self.leaves

    def verify_path(self, path: Path) -> bytes:
        absolute = path.absolute()
        expected = self.leaves.get(absolute)
        if expected is None:
            raise ValueError("generated evidence path is not authenticated")
        raw, identity = _read_bound_regular_file(absolute, MAX_TASK5_DOCUMENT_BYTES)
        if identity != expected[1] or raw != expected[0]:
            raise ValueError("generated evidence changed")
        return raw

    def revalidate(self) -> None:
        self.patch_review_binding.revalidate()
        root = self.generated_root.lstat()
        if (
            not stat.S_ISDIR(root.st_mode)
            or stat.S_ISLNK(root.st_mode)
            or getattr(root, "st_reparse_tag", 0)
            or _filesystem_identity(root) != self.root_identity
        ):
            raise ValueError("generated evidence root changed")
        converter_raw, converter_identity = _read_bound_regular_file(
            self.converter_path, MAX_TASK5_DOCUMENT_BYTES
        )
        if (
            converter_raw != self.converter_raw
            or converter_identity != self.converter_identity
        ):
            raise ValueError("generated evidence converter changed")
        regenerated = self.converter.render_documents(
            self.converter.build_conversion(ROOT)
        )
        if type(regenerated) is not dict or set(regenerated) != GENERATED_EVIDENCE_PATHS or any(
            regenerated.get(relative) != raw
            for relative, raw in self.expected.items()
        ):
            raise ValueError("generated evidence semantics changed")
        _revalidate_exact_generated_tree(self.directories)
        for path in sorted(self.leaves, key=lambda value: str(value).encode("utf-8")):
            self.verify_path(path)
        _revalidate_exact_generated_tree(self.directories)
        final_root = self.generated_root.lstat()
        if _filesystem_identity(final_root) != self.root_identity:
            raise ValueError("generated evidence root changed")
        self.patch_review_binding.revalidate()


def _read_exact_generated_directory(
    path: Path,
    expected: tuple[tuple[str, str], ...],
) -> tuple[int, int]:
    """Bind one small generated directory without accepting extra identities."""

    _validate_bound_path_chain(path)
    before = path.lstat()
    if _ordinary_entry_kind(before) != "directory":
        raise ValueError("generated evidence tree is invalid")
    identity = _directory_identity(before)
    entries: list[tuple[str, str]] = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            if len(entries) >= len(expected):
                raise ValueError("generated evidence tree is invalid")
            metadata = entry.stat(follow_symlinks=False)
            entries.append((entry.name, _ordinary_entry_kind(metadata)))
    actual = tuple(sorted(entries, key=lambda item: item[0].encode("utf-8")))
    after = path.lstat()
    if (
        actual != expected
        or _ordinary_entry_kind(after) != "directory"
        or _directory_identity(after) != identity
    ):
        raise ValueError("generated evidence tree is invalid")
    _validate_bound_path_chain(path)
    return identity


def _bind_exact_generated_tree(
    generated_root: Path,
) -> dict[Path, tuple[tuple[int, int], tuple[tuple[str, str], ...]]]:
    expected = {
        generated_root: (
            ("catalog.json", "regular"),
            ("index.json", "regular"),
            ("mappings", "directory"),
            ("quarantine.json", "regular"),
        ),
        generated_root / "mappings": (
            ("bottle-schemas.json", "regular"),
            ("patches.json", "regular"),
        ),
    }
    return {
        path: (_read_exact_generated_directory(path, entries), entries)
        for path, entries in expected.items()
    }


def _revalidate_exact_generated_tree(
    directories: dict[
        Path,
        tuple[tuple[int, int], tuple[tuple[str, str], ...]],
    ],
) -> None:
    if type(directories) is not dict or len(directories) != 2:
        raise ValueError("generated evidence tree is invalid")
    for path in sorted(directories, key=lambda value: str(value).encode("utf-8")):
        identity, expected = directories[path]
        if _read_exact_generated_directory(path, expected) != identity:
            raise ValueError("generated evidence tree changed")


def _bind_patch_review_directory(
    path: Path,
    *,
    parent_descriptor: object | None = None,
    name: str | None = None,
) -> tuple[object, tuple[int, int]]:
    before = path.lstat()
    if _ordinary_entry_kind(before) != "directory":
        raise ValueError("patch review evidence tree is invalid")
    identity = _directory_identity(before)
    if os.name == "nt" or parent_descriptor is None:
        descriptor, _opened_identity = _bind_validator_directory(path)
    else:
        if type(name) is not str or not name:
            raise ValueError("patch review evidence tree is invalid")
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _directory_identity(opened) != identity
        ):
            _close_validator_directory(descriptor)
            raise ValueError("patch review evidence tree identity changed")
    after = path.lstat()
    if _ordinary_entry_kind(after) != "directory" or _directory_identity(
        after
    ) != identity:
        _close_validator_directory(descriptor)
        raise ValueError("patch review evidence tree identity changed")
    return descriptor, identity


def _open_patch_review_leaf(
    root: Path,
    root_descriptor: object,
    name: str,
) -> tuple[int, tuple[int, int, int, int, int]]:
    path = root / name
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or getattr(before, "st_reparse_tag", 0)
        or before.st_nlink != 1
        or before.st_size > MAX_PATCH_REVIEW_BYTES
    ):
        raise ValueError("patch review evidence leaf is invalid")
    descriptor: int | None = None
    handle: object | None = None
    try:
        if os.name == "nt":
            handle = _VALIDATOR_CREATE_FILE(
                str(path),
                0x80000000 | 0x0080,
                0x00000001,
                None,
                3,
                0x00200000 | 0x08000000,
                None,
            )
            if handle == _VALIDATOR_INVALID_HANDLE:
                raise ValueError("patch review evidence leaf could not be bound")
            descriptor = msvcrt.open_osfhandle(
                int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            handle = None
        else:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        opened = os.fstat(descriptor)
        identity = _held_patch_review_leaf_identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or getattr(opened, "st_reparse_tag", 0)
            or opened.st_nlink != 1
            or opened.st_size > MAX_PATCH_REVIEW_BYTES
            or identity != _held_patch_review_leaf_identity(before)
        ):
            raise ValueError("patch review evidence leaf identity changed")
        after = path.lstat()
        if _held_patch_review_leaf_identity(after) != identity:
            raise ValueError("patch review evidence leaf identity changed")
        return descriptor, identity
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        elif handle is not None and handle != _VALIDATOR_INVALID_HANDLE:
            _VALIDATOR_CLOSE_HANDLE(handle)
        raise


def _read_held_patch_review_leaf(
    descriptor: int,
    expected_identity: tuple[int, int, int, int, int],
) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or getattr(before, "st_reparse_tag", 0)
        or before.st_nlink != 1
        or before.st_size > MAX_PATCH_REVIEW_BYTES
        or _held_patch_review_leaf_identity(before) != expected_identity
    ):
        raise ValueError("patch review evidence leaf changed")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(
            descriptor,
            min(64 * 1024, MAX_PATCH_REVIEW_BYTES + 1 - total),
        )
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_PATCH_REVIEW_BYTES:
            raise ValueError("patch review evidence exceeds the byte limit")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if _held_patch_review_leaf_identity(after) != expected_identity:
        raise ValueError("patch review evidence leaf changed")
    return b"".join(chunks)


def _read_held_patch_review_directory(
    path: Path,
    descriptor: object,
    expected_identity: tuple[int, int],
    expected_children: tuple[tuple[str, str], ...],
) -> None:
    if os.name != "nt":
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _directory_identity(opened) != expected_identity
        ):
            raise ValueError("patch review evidence tree changed")
        scan_target: object = descriptor
    else:
        scan_target = path
    entries: list[tuple[str, str]] = []
    with os.scandir(scan_target) as iterator:
        for entry in iterator:
            if len(entries) >= len(expected_children):
                raise ValueError("patch review evidence tree changed")
            entries.append(
                (
                    entry.name,
                    _ordinary_entry_kind(entry.stat(follow_symlinks=False)),
                )
            )
    actual = tuple(sorted(entries, key=lambda item: item[0].encode("utf-8")))
    current = path.lstat()
    if (
        actual != expected_children
        or _ordinary_entry_kind(current) != "directory"
        or _directory_identity(current) != expected_identity
    ):
        raise ValueError("patch review evidence tree changed")
    if os.name != "nt":
        final = os.fstat(descriptor)
        if _directory_identity(final) != expected_identity:
            raise ValueError("patch review evidence tree changed")


class _PatchReviewBinding:
    """Hold the exact reviewed root and leaf through every repository scan."""

    def __init__(
        self,
        parent: Path,
        parent_descriptor: object,
        parent_identity: tuple[int, int],
        root: Path,
        root_descriptor: object,
        root_identity: tuple[int, int],
        expected_children: tuple[tuple[str, str], ...],
        leaf: Path,
        leaf_descriptor: int,
        raw: bytes,
        leaf_identity: tuple[int, int, int, int, int],
    ) -> None:
        self.parent = parent
        self.parent_descriptor: object | None = parent_descriptor
        self.parent_identity = parent_identity
        self.root = root
        self.root_descriptor: object | None = root_descriptor
        self.root_identity = root_identity
        self.expected_children = expected_children
        self.leaf = leaf
        self.leaf_descriptor: int | None = leaf_descriptor
        self.raw = raw
        self.leaf_identity = leaf_identity

    def close(self) -> None:
        leaf_descriptor = self.leaf_descriptor
        root_descriptor = self.root_descriptor
        parent_descriptor = self.parent_descriptor
        self.leaf_descriptor = None
        self.root_descriptor = None
        self.parent_descriptor = None
        for descriptor, close in (
            (parent_descriptor, _close_validator_directory),
            (root_descriptor, _close_validator_directory),
            (leaf_descriptor, os.close),
        ):
            if descriptor is not None:
                try:
                    close(descriptor)
                except OSError:
                    pass

    def __enter__(self) -> _PatchReviewBinding:
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()

    def contains(self, path: Path) -> bool:
        return path.absolute() == self.leaf

    def _require_open(self) -> tuple[object, int]:
        if self.root_descriptor is None or self.leaf_descriptor is None:
            raise ValueError("patch review evidence binding is closed")
        return self.root_descriptor, self.leaf_descriptor

    def verify_path(self, path: Path) -> bytes:
        if path.absolute() != self.leaf:
            raise ValueError("patch review evidence path is not authenticated")
        root_descriptor, leaf_descriptor = self._require_open()
        raw = _read_held_patch_review_leaf(leaf_descriptor, self.leaf_identity)
        if raw != self.raw:
            raise ValueError("patch review evidence changed")
        if os.name == "nt":
            metadata = self.leaf.lstat()
        else:
            metadata = os.stat(
                self.leaf.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, "st_reparse_tag", 0)
            or _held_patch_review_leaf_identity(metadata) != self.leaf_identity
        ):
            raise ValueError("patch review evidence path changed")
        return raw

    def revalidate(self) -> None:
        root_descriptor, _leaf_descriptor = self._require_open()
        _read_held_patch_review_directory(
            self.root,
            root_descriptor,
            self.root_identity,
            self.expected_children,
        )
        self.verify_path(self.leaf)
        _read_held_patch_review_directory(
            self.root,
            root_descriptor,
            self.root_identity,
            self.expected_children,
        )
        parent = self.parent.lstat()
        if (
            _ordinary_entry_kind(parent) != "directory"
            or _directory_identity(parent) != self.parent_identity
        ):
            raise ValueError("patch review evidence parent changed")
        if os.name != "nt" and self.parent_descriptor is not None:
            opened_parent = os.fstat(self.parent_descriptor)
            if _directory_identity(opened_parent) != self.parent_identity:
                raise ValueError("patch review evidence parent changed")


def _validated_patch_review_binding() -> tuple[_PatchReviewBinding | None, list[str]]:
    """Authenticate and hold the exact canonical reviewed policy independently."""

    parent_descriptor: object | None = None
    root_descriptor: object | None = None
    leaf_descriptor: int | None = None
    binding: _PatchReviewBinding | None = None
    try:
        parent = (ROOT / "migration" / "macwin").absolute()
        _validate_bound_path_chain(parent)
        parent_descriptor, parent_identity = _bind_patch_review_directory(parent)
        root = parent / "reviewed"
        root_descriptor, root_identity = _bind_patch_review_directory(
            root,
            parent_descriptor=parent_descriptor,
            name="reviewed",
        )
        expected_children = tuple(
            sorted(PATCH_REVIEW_TREE.items(), key=lambda item: item[0].encode("ascii"))
        )
        _read_held_patch_review_directory(
            root,
            root_descriptor,
            root_identity,
            expected_children,
        )
        review_relative = PurePosixPath(PATCH_REVIEW_PATH)
        if review_relative.parts != (
            "migration",
            "macwin",
            "reviewed",
            "patches.json",
        ):
            raise ValueError("patch review evidence path is invalid")
        leaf = (ROOT / review_relative).absolute()
        if leaf.parent != root:
            raise ValueError("patch review evidence path is invalid")
        leaf_descriptor, leaf_identity = _open_patch_review_leaf(
            root, root_descriptor, leaf.name
        )
        raw = _read_held_patch_review_leaf(leaf_descriptor, leaf_identity)
        if hashlib.sha256(raw).hexdigest() != PATCH_REVIEW_DOCUMENT_SHA256:
            raise ValueError("patch review evidence digest is invalid")
        _canonical_patch_review_json(raw)
        binding = _PatchReviewBinding(
            parent,
            parent_descriptor,
            parent_identity,
            root,
            root_descriptor,
            root_identity,
            expected_children,
            leaf,
            leaf_descriptor,
            raw,
            leaf_identity,
        )
        parent_descriptor = None
        root_descriptor = None
        leaf_descriptor = None
        binding.revalidate()
    except BaseException as error:
        if binding is not None:
            binding.close()
        if leaf_descriptor is not None:
            os.close(leaf_descriptor)
        if root_descriptor is not None:
            _close_validator_directory(root_descriptor)
        if parent_descriptor is not None:
            _close_validator_directory(parent_descriptor)
        if not isinstance(error, (OSError, RuntimeError, TypeError, ValueError)):
            raise
        return None, ["Mac-Win patch review evidence validation failed"]
    return binding, []


class _DeveloperPathScanError(ValueError):
    """Signal an untrusted ordinary repository path without reflecting it."""


def _ordinary_entry_kind(metadata: os.stat_result) -> str:
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
        raise _DeveloperPathScanError()
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISREG(metadata.st_mode):
        return "regular"
    raise _DeveloperPathScanError()


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    """Return the stable volume/file identity, excluding mutable metadata."""

    return (metadata.st_dev, metadata.st_ino)


def _read_bound_directory(
    path: Path,
) -> tuple[
    tuple[int, int],
    tuple[tuple[str, str], ...],
]:
    try:
        _validate_bound_path_chain(path)
        before = path.lstat()
        if _ordinary_entry_kind(before) != "directory":
            raise _DeveloperPathScanError()
        identity = _directory_identity(before)
        entries: list[tuple[str, str]] = []
        with os.scandir(path) as iterator:
            for entry in iterator:
                if entry.name == ".git":
                    continue
                metadata = entry.stat(follow_symlinks=False)
                entries.append((entry.name, _ordinary_entry_kind(metadata)))
        after = path.lstat()
        if _ordinary_entry_kind(after) != "directory" or _directory_identity(
            after
        ) != identity:
            raise _DeveloperPathScanError()
        _validate_bound_path_chain(path)
    except _DeveloperPathScanError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        raise _DeveloperPathScanError() from None
    return identity, tuple(
        sorted(entries, key=lambda item: item[0].encode("utf-8"))
    )


class _OrdinaryFileBinding:
    """Retain exact ordinary directory and leaf bindings through validation."""

    def __init__(self) -> None:
        self.directories: dict[
            Path,
            tuple[
                tuple[int, int],
                tuple[tuple[str, str], ...],
            ],
        ] = {}
        self.leaves: dict[
            Path, tuple[tuple[int, int], tuple[int, int, int, int, int, int]]
        ] = {}
        self.contents: dict[
            tuple[int, int],
            tuple[bytes | None, bytes, tuple[int, int, int, int, int, int], Path],
        ] = {}

    def add_directory(
        self,
        path: Path,
        expected_entries: tuple[tuple[str, str], ...],
    ) -> None:
        absolute = path.absolute()
        if absolute in self.directories:
            raise _DeveloperPathScanError()
        identity, entries = _read_bound_directory(absolute)
        if entries != expected_entries:
            raise _DeveloperPathScanError()
        self.directories[absolute] = (identity, entries)

    def add(
        self,
        path: Path,
        raw: bytes,
        identity: tuple[int, int, int, int, int, int],
    ) -> None:
        absolute = path.absolute()
        if absolute in self.leaves:
            raise _DeveloperPathScanError()
        key = identity[:2]
        existing = self.contents.get(key)
        if existing is None:
            self.contents[key] = (
                raw if identity[3] > 1 else None,
                hashlib.sha256(raw).digest(),
                identity,
                absolute,
            )
        elif existing[1:3] != (hashlib.sha256(raw).digest(), identity):
            raise _DeveloperPathScanError()
        self.leaves[absolute] = (key, identity)

    def add_alias(
        self,
        path: Path,
        identity: tuple[int, int, int, int, int, int],
    ) -> bytes:
        absolute = path.absolute()
        key = identity[:2]
        existing = self.contents.get(key)
        if absolute in self.leaves or existing is None or existing[2] != identity:
            raise _DeveloperPathScanError()
        self.leaves[absolute] = (key, identity)
        raw = existing[0]
        if raw is None:
            raise _DeveloperPathScanError()
        return raw

    def _revalidate_directories(self) -> None:
        for path in sorted(
            self.directories, key=lambda value: str(value).encode("utf-8")
        ):
            expected_identity, expected_entries = self.directories[path]
            identity, entries = _read_bound_directory(path)
            if identity != expected_identity or entries != expected_entries:
                raise _DeveloperPathScanError()

    def revalidate(self) -> None:
        self._revalidate_directories()
        for key in sorted(self.contents):
            _raw, expected_digest, expected_identity, path = self.contents[key]
            try:
                raw, identity = _read_bound_regular_file(
                    path,
                    MAX_ORDINARY_SCAN_BYTES,
                    require_single_link=False,
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                raise _DeveloperPathScanError() from None
            if (
                identity != expected_identity
                or hashlib.sha256(raw).digest() != expected_digest
            ):
                raise _DeveloperPathScanError()
        for path in sorted(self.leaves, key=lambda value: str(value).encode("utf-8")):
            _key, expected_identity = self.leaves[path]
            try:
                _validate_bound_path_chain(path)
                metadata = path.lstat()
            except (OSError, RuntimeError, TypeError, ValueError):
                raise _DeveloperPathScanError() from None
            if (
                _ordinary_entry_kind(metadata) != "regular"
                or _filesystem_identity(metadata) != expected_identity
            ):
                raise _DeveloperPathScanError()
        self._revalidate_directories()


def _load_task5_converter() -> tuple[
    object,
    Path,
    bytes,
    tuple[int, int, int, int, int, int],
]:
    path = ROOT / "tools" / "convert_macwin_assets.py"
    raw, identity = _read_bound_regular_file(path, MAX_TASK5_DOCUMENT_BYTES)
    module_name = f"_repository_macwin_task5_converter_{id(raw):x}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    finally:
        if sys.modules.get(module_name) is module:
            sys.modules.pop(module_name, None)
    after_raw, after_identity = _read_bound_regular_file(
        path, MAX_TASK5_DOCUMENT_BYTES
    )
    if after_raw != raw or after_identity != identity:
        raise ValueError("generated evidence converter changed")
    return module, path, raw, identity


def _canonical_task5_json(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_TASK5_DOCUMENT_BYTES:
        raise ValueError("generated evidence is oversized")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("generated evidence JSON is invalid") from None
    if type(value) is not dict:
        raise ValueError("generated evidence JSON is invalid")
    canonical = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    if raw != canonical:
        raise ValueError("generated evidence JSON is not canonical")
    return value


def _canonical_patch_review_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or len(raw) > MAX_PATCH_REVIEW_BYTES:
        raise ValueError("patch review evidence is invalid")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("patch review evidence is invalid")
            value[key] = item
        return value

    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("patch review evidence is invalid") from None
    if type(value) is not dict:
        raise ValueError("patch review evidence is invalid")
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if depth > 128:
            raise ValueError("patch review evidence is invalid")
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("patch review evidence is invalid")
            pending.extend((nested, depth + 1) for nested in item.values())
        elif type(item) is list:
            pending.extend((nested, depth + 1) for nested in item)
    canonical = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    if raw != canonical:
        raise ValueError("patch review evidence is invalid")
    return value


def _independent_patch_text(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and all(32 <= ord(character) <= 126 for character in value)
    )


def _independent_patch_relative_path(value: object) -> bool:
    if (
        not _independent_patch_text(value, 1024)
        or value.startswith("/")
        or "\\" in value
        or any(character in '<>:"|?*' for character in value)
    ):
        return False
    segments = value.split("/")
    for segment in segments:
        if (
            not segment
            or len(segment) > 255
            or segment in {".", ".."}
            or segment[-1] in {" ", "."}
        ):
            return False
        reserved_stem = segment.split(".", 1)[0].rstrip(" ")
        if PATCH_RESERVED_SEGMENT.fullmatch(reserved_stem):
            return False
    return True


def _independent_patch_diff_metadata(
    raw: bytes,
) -> tuple[tuple[str, str | None], ...]:
    if type(raw) is not bytes or not 1 <= len(raw) <= 1024 * 1024 or b"\r" in raw:
        raise ValueError("patch source diff evidence is invalid")
    entries: list[tuple[str, str | None]] = []
    current_path: str | None = None
    current_old_blob: str | None = None
    current_has_index = False
    for line in raw.split(b"\n"):
        if line.startswith(b"diff --git "):
            if current_path is not None:
                entries.append((current_path, current_old_blob))
            if not line.startswith(b"diff --git a/"):
                raise ValueError("patch source diff evidence is invalid")
            left, separator, right = line[len(b"diff --git a/") :].partition(b" b/")
            if not separator or b" b/" in right or left != right:
                raise ValueError("patch source diff evidence is invalid")
            try:
                current_path = left.decode("ascii", errors="strict")
            except UnicodeDecodeError:
                raise ValueError("patch source diff evidence is invalid") from None
            if not _independent_patch_relative_path(current_path):
                raise ValueError("patch source diff evidence is invalid")
            current_old_blob = None
            current_has_index = False
        elif line.startswith(b"index "):
            match = PATCH_INDEX_LINE.fullmatch(line)
            if current_path is None or current_has_index or match is None:
                raise ValueError("patch source diff evidence is invalid")
            current_old_blob = match.group(1).decode("ascii")
            current_has_index = True
    if current_path is not None:
        entries.append((current_path, current_old_blob))
    if not 1 <= len(entries) <= 128:
        raise ValueError("patch source diff evidence is invalid")
    entries.sort(key=lambda item: item[0].encode("ascii"))
    if len({path.casefold() for path, _old_blob in entries}) != len(entries):
        raise ValueError("patch source diff evidence is invalid")
    return tuple(entries)


def _independent_patch_mail_identity(
    source_binding: object, asset: dict[str, object]
) -> tuple[str | None, dict[str, object], bytes]:
    object_path = asset.get("objectPath")
    if type(object_path) is not str:
        raise ValueError("patch source object identity is invalid")
    raw = source_binding.verify_path(
        source_binding.root / PurePosixPath(object_path)
    )
    if type(raw) is not bytes or len(raw) != asset.get("byteSize"):
        raise ValueError("patch source object identity is invalid")
    if not raw.startswith(b"From "):
        return None, {"status": "unresolved"}, raw
    header_end = raw.find(b"\n\n")
    if not 0 < header_end <= 16 * 1024 or b"\r" in raw[:header_end]:
        raise ValueError("patch source mail identity is invalid")
    try:
        lines = raw[:header_end].decode("ascii", errors="strict").split("\n")
    except UnicodeDecodeError:
        raise ValueError("patch source mail identity is invalid") from None
    if not lines or re.fullmatch(
        r"From [0-9a-f]{40} Mon Sep 17 00:00:00 2001", lines[0]
    ) is None:
        raise ValueError("patch source mail identity is invalid")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ": " not in line:
            raise ValueError("patch source mail identity is invalid")
        key, value = line.split(": ", 1)
        if key in headers:
            raise ValueError("patch source mail identity is invalid")
        headers[key] = value
    if set(headers) != {"From", "Date", "Subject"}:
        raise ValueError("patch source mail identity is invalid")
    subject = headers["Subject"]
    author_match = PATCH_MAIL_AUTHOR.fullmatch(headers["From"])
    if (
        not _independent_patch_text(subject, 256)
        or not _independent_patch_text(headers["Date"], 128)
        or author_match is None
    ):
        raise ValueError("patch source mail identity is invalid")
    return (
        subject,
        {
            "displayName": author_match.group(1),
            "email": author_match.group(2),
            "evidence": "frozen-patch-mail-header",
            "status": "reviewed",
        },
        raw,
    )


def _independent_patch_author(author: object) -> bool:
    if type(author) is not dict or not {"status"}.issubset(author):
        return False
    status = author.get("status")
    if status == "reviewed":
        return (
            set(author) == {"displayName", "email", "evidence", "status"}
            and type(author.get("displayName")) is str
            and 1 <= len(author["displayName"]) <= 256
            and type(author.get("email")) is str
            and 3 <= len(author["email"]) <= 254
            and author.get("evidence") == "frozen-patch-mail-header"
        )
    if status == "unresolved":
        return set(author).issubset(
            {"displayName", "email", "evidence", "status"}
        ) and all(
            author.get(optional) is None
            for optional in ("displayName", "email", "evidence")
            if optional in author
        )
    return False


def _independent_patch_dependencies(
    dependencies: object, asset: dict[str, object]
) -> list[dict[str, str]]:
    if type(dependencies) is not list or len(dependencies) > 128:
        raise ValueError("patch review dependency evidence is invalid")
    keys: list[tuple[str, str]] = []
    for dependency in dependencies:
        if (
            type(dependency) is not dict
            or set(dependency) != {"kind", "value"}
            or dependency.get("kind")
            not in {
                "patch-license",
                "external-dependency",
                "development-dependency",
            }
            or not _independent_patch_text(dependency.get("value"), 2048)
            or (
                dependency["kind"] in {"patch-license", "external-dependency"}
                and PATCH_HTTPS_EVIDENCE.fullmatch(dependency["value"]) is None
            )
        ):
            raise ValueError("patch review dependency evidence is invalid")
        keys.append((dependency["kind"], dependency["value"]))
    if keys != sorted(set(keys)):
        raise ValueError("patch review dependency evidence is invalid")
    external_refs = asset.get("externalRefs")
    development_dependencies = asset.get("developmentDependencies")
    if type(external_refs) is not list or type(development_dependencies) is not list:
        raise ValueError("patch source dependency evidence is invalid")
    expected = [
        {"kind": "development-dependency", "value": value}
        for value in development_dependencies
    ] + [
        {"kind": "external-dependency", "value": value}
        for value in external_refs
    ]
    expected.sort(key=lambda item: (item["kind"], item["value"]))
    if dependencies != expected:
        raise ValueError("patch source dependency evidence is invalid")
    return expected


def _independent_patch_preimages(
    preimages: object,
    source_metadata: tuple[tuple[str, str | None], ...],
) -> dict[str, int]:
    if type(preimages) is not list or not 1 <= len(preimages) <= 128:
        raise ValueError("patch review base evidence is invalid")
    paths: list[str] = []
    old_blobs: list[tuple[str, str | None]] = []
    counts = {"matched": 0, "mismatched": 0, "added": 0, "unproven": 0}
    for preimage in preimages:
        if (
            type(preimage) is not dict
            or set(preimage)
            != {"path", "patchOldBlob", "upstreamBlobOid", "result"}
            or not _independent_patch_relative_path(preimage.get("path"))
            or preimage.get("result") not in counts
        ):
            raise ValueError("patch review base evidence is invalid")
        path = preimage["path"]
        result = preimage["result"]
        patch_old = preimage["patchOldBlob"]
        upstream = preimage["upstreamBlobOid"]
        if result in {"matched", "mismatched"}:
            if (
                type(patch_old) is not str
                or PATCH_GIT_PREFIX.fullmatch(patch_old) is None
                or type(upstream) is not str
                or PATCH_GIT_OID.fullmatch(upstream) is None
                or (result == "matched") != upstream.startswith(patch_old)
            ):
                raise ValueError("patch review base evidence is invalid")
        elif result == "added":
            if (
                type(patch_old) is not str
                or PATCH_ZERO_GIT_PREFIX.fullmatch(patch_old) is None
                or upstream is not None
            ):
                raise ValueError("patch review base evidence is invalid")
        elif (
            patch_old is not None
            and (
                type(patch_old) is not str
                or PATCH_ANY_GIT_PREFIX.fullmatch(patch_old) is None
            )
        ) or (
            upstream is not None
            and (
                type(upstream) is not str
                or PATCH_GIT_OID.fullmatch(upstream) is None
            )
        ):
            raise ValueError("patch review base evidence is invalid")
        paths.append(path)
        old_blobs.append((path, patch_old))
        counts[result] += 1
    if (
        paths != sorted(paths, key=lambda value: value.encode("ascii"))
        or len({path.casefold() for path in paths}) != len(paths)
        or tuple(old_blobs) != source_metadata
    ):
        raise ValueError("patch review base evidence is invalid")
    return counts


def _independent_patch_review_oracle(
    source_binding: object,
    review_raw: bytes,
    documents: dict[str, bytes],
) -> None:
    """Rebuild the exact patch decision without converter policy callbacks."""

    if (
        type(review_raw) is not bytes
        or hashlib.sha256(review_raw).hexdigest() != PATCH_REVIEW_DOCUMENT_SHA256
        or type(documents) is not dict
        or set(documents) != TASK6_EVIDENCE_PATHS
    ):
        raise ValueError("patch review evidence is invalid")
    review = _canonical_patch_review_json(review_raw)
    if set(review) != {"schemaVersion", "source", "recordCount", "records"}:
        raise ValueError("patch review evidence is invalid")
    review_records = review.get("records")
    if (
        review.get("schemaVersion") != "1"
        or review.get("source") != PATCH_REVIEW_SOURCE
        or review.get("recordCount") != 11
        or type(review_records) is not list
        or len(review_records) != 11
    ):
        raise ValueError("patch review evidence is invalid")
    manifest = source_binding.manifest
    assets = manifest.get("assets") if type(manifest) is dict else None
    if type(assets) is not list or len(assets) != 90:
        raise ValueError("patch review source evidence is invalid")
    patch_assets = sorted(
        (
            asset
            for asset in assets
            if type(asset) is dict and asset.get("category") == "patches"
        ),
        key=lambda asset: asset["sourcePath"].encode("ascii"),
    )
    if len(patch_assets) != 11:
        raise ValueError("patch review source evidence is invalid")
    if any(type(record) is not dict for record in review_records):
        raise ValueError("patch review coverage is invalid")
    review_paths = [record.get("sourcePath") for record in review_records]
    expected_paths = [asset["sourcePath"] for asset in patch_assets]
    if (
        any(type(path) is not str for path in review_paths)
        or review_paths != expected_paths
        or review_paths != sorted(review_paths, key=lambda value: value.encode("ascii"))
        or len({path.casefold() for path in review_paths}) != 11
        or set(PATCH_APPLICATIONS) != set(expected_paths)
    ):
        raise ValueError("patch review coverage is invalid")

    expected_mapping: list[dict[str, object]] = []
    expected_quarantine: list[dict[str, object]] = []
    preimage_evidence: list[dict[str, object]] = []
    preimage_count = 0
    record_fields = {
        "sourcePath",
        "sourceSha256",
        "gitBlobOid",
        "gitMode",
        "byteSize",
        "subject",
        "purpose",
        "affectedApplications",
        "upstream",
        "preimages",
        "patchAuthor",
        "projectLicense",
        "patchLicense",
        "evidenceAndDependencies",
        "upstreamStatus",
        "reviewDisposition",
        "reason",
        "releaseCondition",
        "regressionProbeIds",
    }
    for record, asset in zip(review_records, patch_assets, strict=True):
        if type(record) is not dict or set(record) != record_fields:
            raise ValueError("patch review record is invalid")
        path = record["sourcePath"]
        if (
            record.get("sourceSha256") != asset.get("sha256")
            or record.get("gitBlobOid") != asset.get("gitBlobOid")
            or record.get("gitMode") != asset.get("gitMode")
            or record.get("byteSize") != asset.get("byteSize")
            or type(record.get("byteSize")) is not int
            or not 1 <= record["byteSize"] <= 1024 * 1024
            or not _independent_patch_text(record.get("purpose"), 2048)
            or record.get("upstreamStatus") != "unresolved"
            or record.get("reviewDisposition") != "quarantined"
            or record.get("reason") != "missing-license"
            or record.get("releaseCondition") != PATCH_MISSING_LICENSE_RELEASE
            or record.get("regressionProbeIds") != []
            or record.get("patchLicense") != {"status": "unresolved"}
        ):
            raise ValueError("patch review record is invalid")
        expected_upstream = (
            PATCH_UPSTREAM_JASP
            if path.startswith("patches/jasp-")
            else PATCH_UPSTREAM_WINE
            if path.startswith("patches/wine-")
            else None
        )
        if expected_upstream is None or record.get("upstream") != expected_upstream:
            raise ValueError("patch review upstream evidence is invalid")
        expected_subject, expected_author, patch_raw = _independent_patch_mail_identity(
            source_binding, asset
        )
        subject = record.get("subject")
        if (
            subject != expected_subject
            or (
                subject is not None
                and not _independent_patch_text(subject, 256)
            )
        ):
            raise ValueError("patch review subject evidence is invalid")
        author = record.get("patchAuthor")
        if not _independent_patch_author(author) or author != expected_author:
            raise ValueError("patch review author evidence is invalid")
        applications = record.get("affectedApplications")
        expected_applications = PATCH_APPLICATIONS.get(path)
        if (
            type(applications) is not list
            or not 1 <= len(applications) <= 32
            or any(
                type(item) is not str or PATCH_IDENTIFIER.fullmatch(item) is None
                for item in applications
            )
            or applications
            != sorted(set(applications), key=lambda value: value.encode("ascii"))
            or tuple(applications) != expected_applications
        ):
            raise ValueError("patch review application evidence is invalid")
        preimages = record.get("preimages")
        source_metadata = _independent_patch_diff_metadata(patch_raw)
        base_counts = _independent_patch_preimages(preimages, source_metadata)
        preimage_evidence.append(
            {
                "sourcePath": path,
                "preimages": [
                    {
                        "path": preimage["path"],
                        "result": preimage["result"],
                        "upstreamBlobOid": preimage["upstreamBlobOid"],
                    }
                    for preimage in preimages
                ],
            }
        )
        preimage_count += len(preimages)
        project_license = record.get("projectLicense")
        expected_project_license = (
            {
                "contextOnly": True,
                "evidenceLocator": (
                    "https://github.com/jasp-stats/jasp-desktop/blob/"
                    "28be3fee5c7ce2119f1945acd0254eb4fb8cb6e2/"
                    "Docs/development/jasp-licensing.md"
                ),
                "spdxExpression": "AGPL-3.0-or-later",
            }
            if path.startswith("patches/jasp-")
            else {
                "contextOnly": True,
                "evidenceLocator": (
                    "https://gitlab.winehq.org/wine/wine/-/blob/"
                    "f6c044e1890e84a4aa5e77e76ba7276a615630e1/LICENSE"
                ),
                "spdxExpression": "LGPL-2.1-or-later",
            }
        )
        if project_license != expected_project_license:
            raise ValueError("patch review project license is invalid")
        dependencies = _independent_patch_dependencies(
            record.get("evidenceAndDependencies"), asset
        )
        expected_mapping.append(
            {
                "sourceRepository": TASK5_SOURCE_REPOSITORY,
                "sourcePath": path,
                "sourceCommit": asset["sourceCommit"],
                "gitBlobOid": asset["gitBlobOid"],
                "gitMode": asset["gitMode"],
                "sourceSha256": asset["sha256"],
                "category": "patches",
                "status": "quarantined",
                "targetIssue": "MW-ASSET-002",
                "intendedOwner": "compatforge/patches",
                "license": asset["license"],
                "provenance": asset["provenance"],
                "purpose": record["purpose"],
                "affectedApplications": applications,
                "upstream": expected_upstream,
                "baseEvidence": base_counts,
                "patchAuthor": author,
                "projectLicense": project_license,
                "patchLicense": {"status": "unresolved"},
                "evidenceAndDependencies": dependencies,
                "upstreamStatus": "unresolved",
                "reviewDisposition": "quarantined",
                "reason": "missing-license",
                "releaseCondition": PATCH_MISSING_LICENSE_RELEASE,
                "regressionProbeIds": [],
            }
        )
        expected_quarantine.append(
            {
                "sourcePath": path,
                "sourceCommit": asset["sourceCommit"],
                "sourceSha256": asset["sha256"],
                "category": "patches",
                "status": "quarantined",
                "reason": "missing-license",
                "evidenceLocators": [f"{path}#patchLicense"],
                "intendedOwner": "compatforge/patches",
                "releaseCondition": PATCH_MISSING_LICENSE_RELEASE,
            }
        )

    preimage_evidence_raw = json.dumps(
        preimage_evidence,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if (
        len(preimage_evidence) != PATCH_PREIMAGE_RECORD_COUNT
        or preimage_count != PATCH_PREIMAGE_COUNT
        or hashlib.sha256(preimage_evidence_raw).hexdigest()
        != PATCH_PREIMAGE_EVIDENCE_SHA256
    ):
        raise ValueError("patch review canonical preimage evidence is invalid")

    mapping_raw = documents.get(
        "migration/macwin/generated/mappings/patches.json"
    )
    quarantine_raw = documents.get("migration/macwin/generated/quarantine.json")
    if (
        type(mapping_raw) is not bytes
        or hashlib.sha256(mapping_raw).hexdigest()
        != TASK6_DOCUMENT_SHA256[
            "migration/macwin/generated/mappings/patches.json"
        ]
        or type(quarantine_raw) is not bytes
        or hashlib.sha256(quarantine_raw).hexdigest()
        != TASK5_DOCUMENT_SHA256["migration/macwin/generated/quarantine.json"]
    ):
        raise ValueError("patch generated evidence digest is invalid")
    mapping = _canonical_task5_json(mapping_raw)
    quarantine = _canonical_task5_json(quarantine_raw)
    quarantine_records = quarantine.get("records")
    if (
        mapping
        != {"schemaVersion": "1", "records": expected_mapping}
        or type(quarantine_records) is not list
        or len(quarantine_records) != 84
        or [item.get("sourcePath") for item in quarantine_records if type(item) is dict]
        != sorted(
            (item.get("sourcePath") for item in quarantine_records if type(item) is dict),
            key=lambda value: value.encode("ascii"),
        )
        or [
            item
            for item in quarantine_records
            if type(item) is dict and item.get("category") == "patches"
        ]
        != expected_quarantine
    ):
        raise ValueError("patch generated evidence semantics are invalid")
    if {
        "converted": 2,
        "deferred": 4,
        "quarantined": 84,
    } != {
        "converted": 2,
        "deferred": sum(asset.get("category") == "bottle-schema" for asset in assets),
        "quarantined": len(assets) - 2 - sum(
            asset.get("category") == "bottle-schema" for asset in assets
        ),
    }:
        raise ValueError("patch migration status counts are invalid")


def _independent_task5_oracle(
    source_binding: object,
    documents: dict[str, bytes],
) -> None:
    """Authenticate the fixed real Task 5 ledger without converter callbacks."""

    if type(documents) is not dict or set(documents) != TASK5_DOCUMENT_PATHS:
        raise ValueError("generated evidence set is invalid")
    for relative, expected_digest in TASK5_DOCUMENT_SHA256.items():
        raw = documents.get(relative)
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != expected_digest:
            raise ValueError("generated evidence digest is invalid")
    catalog = _canonical_task5_json(
        documents["migration/macwin/generated/catalog.json"]
    )
    quarantine = _canonical_task5_json(
        documents["migration/macwin/generated/quarantine.json"]
    )
    manifest = source_binding.manifest
    if (
        type(manifest) is not dict
        or manifest.get("repository") != TASK5_SOURCE_REPOSITORY
        or manifest.get("sourceCommit") != TASK5_SOURCE_COMMIT
        or type(manifest.get("assets")) is not list
    ):
        raise ValueError("source evidence identity is invalid")
    assets = {
        item["sourcePath"]: item
        for item in manifest["assets"]
        if type(item) is dict and type(item.get("sourcePath")) is str
    }
    recipe_paths = sorted(
        (
            path
            for path in assets
            if path.startswith(f"{TASK5_CATALOG_ROOT}/recipes/")
        ),
        key=lambda value: value.encode("ascii"),
    )
    if len(recipe_paths) != 17:
        raise ValueError("source recipe coverage is invalid")
    expected_candidates: list[dict[str, object]] = []
    expected_records: list[dict[str, object]] = []
    for path in recipe_paths:
        asset = assets[path]
        raw = source_binding.verify_path(
            source_binding.root / PurePosixPath(asset["objectPath"])
        )
        try:
            source = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("source recipe JSON is invalid") from None
        if (
            type(source) is not dict
            or type(source.get("id")) is not str
            or type(source.get("name")) is not str
            or asset.get("category") != "catalog"
            or asset.get("intendedOwner") != "compatforge/catalog"
            or asset.get("sourceCommit") != TASK5_SOURCE_COMMIT
            or asset.get("license") != {"status": "unresolved"}
            or asset.get("provenance") != {"status": "unresolved"}
        ):
            raise ValueError("source recipe evidence is invalid")
        expected_candidates.append(
            {
                "id": source["id"],
                "name": source["name"],
                "reason": "missing-license",
                "sourceCommit": TASK5_SOURCE_COMMIT,
                "sourcePath": path,
                "sourceSha256": asset["sha256"],
                "status": "quarantined",
            }
        )
        expected_records.append(
            {
                "sourcePath": path,
                "sourceCommit": TASK5_SOURCE_COMMIT,
                "sourceSha256": asset["sha256"],
                "category": "catalog",
                "status": "quarantined",
                "reason": "missing-license",
                "intendedOwner": "compatforge/catalog",
            }
        )
    if (
        set(catalog)
        != {
            "schemaVersion", "sourceRepository", "sourceCommit", "catalogBoundary",
            "candidateCount", "convertedCount", "quarantinedCount", "candidates",
        }
        or catalog.get("schemaVersion") != "1"
        or catalog.get("sourceRepository") != TASK5_SOURCE_REPOSITORY
        or catalog.get("sourceCommit") != TASK5_SOURCE_COMMIT
        or catalog.get("candidateCount") != 17
        or catalog.get("convertedCount") != 0
        or catalog.get("quarantinedCount") != 17
        or catalog.get("candidates") != expected_candidates
    ):
        raise ValueError("generated catalog semantics are invalid")
    boundary = catalog["catalogBoundary"]
    if type(boundary) is not dict or set(boundary) != {"index", "signature"}:
        raise ValueError("generated catalog boundary is invalid")
    for label, path in (("index", TASK5_CATALOG_INDEX), ("signature", TASK5_CATALOG_SIGNATURE)):
        asset = assets.get(path)
        if boundary.get(label) != {
            "sourceCommit": TASK5_SOURCE_COMMIT,
            "sourcePath": path,
            "sourceSha256": asset.get("sha256") if type(asset) is dict else None,
        }:
            raise ValueError("generated catalog boundary is invalid")
    records = quarantine.get("records")
    if (
        set(quarantine) != {"schemaVersion", "records"}
        or quarantine.get("schemaVersion") != "1"
        or type(records) is not list
        or len(records) != 84
    ):
        raise ValueError("generated quarantine semantics are invalid")
    catalog_records = {
        record.get("sourcePath"): record
        for record in records
        if type(record) is dict and record.get("category") == "catalog"
    }
    if set(catalog_records) != {
        record["sourcePath"] for record in expected_records
    }:
        raise ValueError("generated quarantine catalog coverage is invalid")
    for expected in expected_records:
        actual = catalog_records[expected["sourcePath"]]
        if (
            type(actual) is not dict
            or set(actual)
            != {
                "sourcePath", "sourceCommit", "sourceSha256", "category", "status",
                "reason", "evidenceLocators", "intendedOwner", "releaseCondition",
            }
            or any(actual.get(key) != value for key, value in expected.items())
            or type(actual.get("evidenceLocators")) is not list
            or not actual["evidenceLocators"]
            or actual["evidenceLocators"]
            != sorted(set(actual["evidenceLocators"]), key=lambda value: value.encode("utf-8"))
            or f'{actual["sourcePath"]}#license' not in actual["evidenceLocators"]
            or actual.get("releaseCondition")
            != "Record a reviewed source license and regenerate the migration."
        ):
            raise ValueError("generated quarantine record is invalid")


def _independent_task6_oracle(
    source_binding: object,
    review_raw: bytes,
    documents: dict[str, bytes],
) -> None:
    """Independently close every real Task 6 mapping and quarantine decision."""

    if type(documents) is not dict or set(documents) != TASK6_EVIDENCE_PATHS:
        raise ValueError("generated evidence set is invalid")
    for relative, expected_digest in TASK6_DOCUMENT_SHA256.items():
        raw = documents.get(relative)
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != expected_digest:
            raise ValueError("Task 6 generated evidence digest is invalid")
    manifest = source_binding.manifest
    assets = manifest.get("assets") if type(manifest) is dict else None
    if type(assets) is not list:
        raise ValueError("source evidence identity is invalid")
    by_category: dict[str, list[dict[str, object]]] = {
        "patches": [],
        "bottle-schema": [],
        "probes": [],
        "fixtures": [],
    }
    for asset in assets:
        if type(asset) is not dict:
            raise ValueError("source evidence identity is invalid")
        category = asset.get("category")
        if category in by_category:
            by_category[category].append(asset)
    if {key: len(value) for key, value in by_category.items()} != {
        "patches": 11,
        "bottle-schema": 4,
        "probes": 26,
        "fixtures": 30,
    }:
        raise ValueError("Task 6 source coverage is invalid")

    bottle_relative = "migration/macwin/generated/mappings/bottle-schemas.json"
    bottle_mapping = _canonical_task5_json(documents[bottle_relative])
    expected_bottles = [
        {
            "sourceRepository": TASK5_SOURCE_REPOSITORY,
            "sourcePath": asset["sourcePath"],
            "sourceCommit": asset["sourceCommit"],
            "gitBlobOid": asset["gitBlobOid"],
            "gitMode": asset["gitMode"],
            "sourceSha256": asset["sha256"],
            "category": "bottle-schema",
            "status": "deferred",
            "targetIssue": "MW-ASSET-003",
            "intendedOwner": "compatforge/bottle-schema",
            "license": asset["license"],
            "provenance": asset["provenance"],
        }
        for asset in by_category["bottle-schema"]
    ]
    if bottle_mapping != {"schemaVersion": "1", "records": expected_bottles}:
        raise ValueError("deferred Bottle mapping semantics are invalid")

    _independent_patch_review_oracle(source_binding, review_raw, documents)

    quarantine = _canonical_task5_json(
        documents["migration/macwin/generated/quarantine.json"]
    )
    records = quarantine.get("records")
    if type(records) is not list or len(records) != 84:
        raise ValueError("Task 6 quarantine coverage is invalid")
    task6_assets = sorted(
        (*by_category["probes"], *by_category["fixtures"]),
        key=lambda asset: asset["sourcePath"].encode("ascii"),
    )
    task6_records = {
        record.get("sourcePath"): record
        for record in records
        if type(record) is dict
        and record.get("category") in {"probes", "fixtures"}
    }
    if set(task6_records) != {asset["sourcePath"] for asset in task6_assets}:
        raise ValueError("Task 6 quarantine coverage is invalid")
    for asset in task6_assets:
        record = task6_records[asset["sourcePath"]]
        evidence = sorted(
            {
                f'{asset["sourcePath"]}#license',
                f'{asset["sourcePath"]}#provenance',
                *asset["externalRefs"],
                *asset["developmentDependencies"],
            },
            key=lambda value: value.encode("utf-8"),
        )
        expected = {
            "sourcePath": asset["sourcePath"],
            "sourceCommit": asset["sourceCommit"],
            "sourceSha256": asset["sha256"],
            "category": asset["category"],
            "status": "quarantined",
            "reason": "missing-license",
            "evidenceLocators": evidence,
            "intendedOwner": asset["intendedOwner"],
            "releaseCondition": "Record a reviewed source license and regenerate the migration.",
        }
        if record != expected:
            raise ValueError("Task 6 quarantine semantics are invalid")


def _independent_task7_oracle(
    source_binding: object,
    documents: dict[str, bytes],
) -> None:
    """Independently authenticate the fixed real Task 7 root seal."""

    if type(documents) is not dict or set(documents) != GENERATED_EVIDENCE_PATHS:
        raise ValueError("generated graph set is invalid")
    raw = documents["migration/macwin/generated/index.json"]
    if hashlib.sha256(raw).hexdigest() != TASK7_DOCUMENT_SHA256[
        "migration/macwin/generated/index.json"
    ]:
        raise ValueError("Task 7 generated graph digest is invalid")
    root = _canonical_task5_json(raw)
    manifest = source_binding.manifest
    assets = manifest.get("assets") if type(manifest) is dict else None
    if type(assets) is not list or len(assets) != 90:
        raise ValueError("Task 7 source coverage is invalid")
    expected_source = {
        "repository": TASK5_SOURCE_REPOSITORY,
        "sourceTag": "mw-migration-baseline-db12d5e",
        "sourceTagObject": "9f10d003382ce7ffbb269376c03477e17516302f",
        "sourceCommit": TASK5_SOURCE_COMMIT,
        "inventoryCommit": "97f8423094d25325d8f864eb6f49a9e8628dbb93",
        "digestAlgorithm": "sha256",
    }
    expected_document_kinds = {
        "migration/macwin/generated/catalog.json": "catalog",
        "migration/macwin/generated/mappings/bottle-schemas.json": "deferred-mapping",
        "migration/macwin/generated/mappings/patches.json": "deferred-mapping",
        "migration/macwin/generated/quarantine.json": "quarantine",
    }
    expected_documents = [
        {
            "path": path,
            "kind": expected_document_kinds[path],
            "byteSize": len(documents[path]),
            "sha256": hashlib.sha256(documents[path]).hexdigest(),
            "references": [],
        }
        for path in sorted(expected_document_kinds, key=lambda value: value.encode("ascii"))
    ]
    expected_records: list[dict[str, object]] = []
    category_counts = {
        "bottle-schema": 0,
        "catalog": 0,
        "fixtures": 0,
        "patches": 0,
        "probes": 0,
    }
    status_counts = {"converted": 0, "deferred": 0, "quarantined": 0}
    for asset in sorted(assets, key=lambda item: item["sourcePath"].encode("ascii")):
        if type(asset) is not dict:
            raise ValueError("Task 7 source identity is invalid")
        category = asset.get("category")
        path = asset.get("sourcePath")
        if category not in category_counts or type(path) is not str:
            raise ValueError("Task 7 source identity is invalid")
        category_counts[category] += 1
        if path in {TASK5_CATALOG_INDEX, TASK5_CATALOG_SIGNATURE}:
            status = "converted"
            document_path = "migration/macwin/generated/catalog.json"
        elif category == "catalog" or category in {"fixtures", "probes"}:
            status = "quarantined"
            document_path = "migration/macwin/generated/quarantine.json"
        elif category == "patches":
            status = "quarantined"
            document_path = "migration/macwin/generated/quarantine.json"
        elif category == "bottle-schema":
            status = "deferred"
            document_path = "migration/macwin/generated/mappings/bottle-schemas.json"
        else:
            raise ValueError("Task 7 source classification is invalid")
        status_counts[status] += 1
        expected_records.append(
            {
                "sourcePath": path,
                "sourceCommit": asset.get("sourceCommit"),
                "sourceSha256": asset.get("sha256"),
                "category": category,
                "status": status,
                "documentPath": document_path,
            }
        )
    if (
        set(root)
        != {
            "schemaVersion", "source", "recordCount", "categoryCounts",
            "statusCounts", "documentCount", "documents", "records",
        }
        or root.get("schemaVersion") != "1"
        or root.get("source") != expected_source
        or root.get("recordCount") != 90
        or root.get("categoryCounts")
        != {
            "bottleSchema": 4,
            "catalog": 19,
            "fixtures": 30,
            "patches": 11,
            "probes": 26,
        }
        or category_counts
        != {"bottle-schema": 4, "catalog": 19, "fixtures": 30, "patches": 11, "probes": 26}
        or root.get("statusCounts") != status_counts
        or status_counts != {"converted": 2, "deferred": 4, "quarantined": 84}
        or root.get("documentCount") != 4
        or root.get("documents") != expected_documents
        or root.get("records") != expected_records
    ):
        raise ValueError("Task 7 generated graph semantics are invalid")


def _validated_macwin_generated_evidence_binding(
    source_binding: object,
    patch_review_binding: _PatchReviewBinding,
) -> tuple[
    _GeneratedEvidenceBinding | None, list[str]
]:
    """Rebuild, compare, and bind the complete Task 7 generated graph."""

    try:
        converter, converter_path, converter_raw, converter_identity = (
            _load_task5_converter()
        )
        expected = converter.render_documents(converter.build_conversion(ROOT))
        if type(expected) is not dict or set(expected) != GENERATED_EVIDENCE_PATHS:
            raise ValueError("generated evidence set is invalid")
        selected = {relative: expected[relative] for relative in GENERATED_EVIDENCE_PATHS}
        if any(
            type(raw) is not bytes or len(raw) > MAX_TASK5_DOCUMENT_BYTES
            for raw in selected.values()
        ):
            raise ValueError("generated evidence bytes are invalid")
        generated_root = (ROOT / "migration" / "macwin" / "generated").absolute()
        root = generated_root.lstat()
        if (
            not stat.S_ISDIR(root.st_mode)
            or stat.S_ISLNK(root.st_mode)
            or getattr(root, "st_reparse_tag", 0)
        ):
            raise ValueError("generated evidence root is invalid")
        root_identity = _filesystem_identity(root)
        directories = _bind_exact_generated_tree(generated_root)
        leaves: dict[
            Path, tuple[bytes, tuple[int, int, int, int, int, int]]
        ] = {}
        committed: dict[str, bytes] = {}
        for relative in sorted(selected, key=lambda value: value.encode("ascii")):
            path = (ROOT / PurePosixPath(relative)).absolute()
            raw, identity = _read_bound_regular_file(path, MAX_TASK5_DOCUMENT_BYTES)
            if raw != selected[relative] or hashlib.sha256(raw).digest() != hashlib.sha256(selected[relative]).digest():
                raise ValueError("generated evidence bytes do not match")
            leaves[path] = (raw, identity)
            committed[relative] = raw
        _independent_task5_oracle(
            source_binding,
            {relative: committed[relative] for relative in TASK5_DOCUMENT_PATHS},
        )
        _independent_task6_oracle(
            source_binding,
            patch_review_binding.raw,
            {relative: committed[relative] for relative in TASK6_EVIDENCE_PATHS},
        )
        _independent_task7_oracle(source_binding, committed)
        if len(leaves) != 5:
            raise ValueError("generated evidence leaf set is invalid")
        binding = _GeneratedEvidenceBinding(
            generated_root,
            root_identity,
            selected,
            leaves,
            directories,
            converter,
            converter_path,
            converter_raw,
            converter_identity,
            patch_review_binding,
        )
        binding.revalidate()
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return None, ["Mac-Win generated evidence validation failed"]
    return binding, []


def _scan_developer_paths(
    source_binding: object | None,
    generated_binding: _GeneratedEvidenceBinding | None = None,
    patch_review_binding: _PatchReviewBinding | None = None,
) -> tuple[list[str], _OrdinaryFileBinding]:
    errors: list[str] = []
    ordinary_binding = _OrdinaryFileBinding()
    forbidden = ("/Users/a1-6/", "/home/a1-6/")
    paths: list[Path] = []
    try:
        for path in ROOT.rglob("*"):
            if ".git" in path.parts:
                continue
            if len(paths) >= MAX_ORDINARY_SCAN_ENTRIES:
                raise _DeveloperPathScanError()
            paths.append(path)
        paths.sort()
    except _DeveloperPathScanError:
        raise
    except OSError:
        raise _DeveloperPathScanError() from None
    entries: list[tuple[Path, str, tuple[int, int, int, int, int, int] | None]] = []
    expected_children: dict[Path, list[tuple[str, str]]] = {
        ROOT.absolute(): []
    }
    for path in paths:
        try:
            metadata = path.lstat()
            kind = _ordinary_entry_kind(metadata)
        except _DeveloperPathScanError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError):
            raise _DeveloperPathScanError() from None
        absolute = path.absolute()
        entries.append(
            (
                absolute,
                kind,
                _filesystem_identity(metadata) if kind == "regular" else None,
            )
        )
        expected_children.setdefault(absolute.parent, []).append(
            (absolute.name, kind)
        )
        if kind == "directory":
            expected_children.setdefault(absolute, [])

    for directory in sorted(
        expected_children, key=lambda value: str(value).encode("utf-8")
    ):
        expected = tuple(
            sorted(
                expected_children[directory],
                key=lambda item: item[0].encode("utf-8"),
            )
        )
        ordinary_binding.add_directory(directory, expected)

    unique_bytes = 0
    for path, kind, enumerated_identity in entries:
        if kind == "directory":
            continue
        if source_binding is not None and source_binding.contains(path):
            source_binding.verify_path(path)
            continue
        if generated_binding is not None and generated_binding.contains(path):
            generated_binding.verify_path(path)
            continue
        if patch_review_binding is not None and patch_review_binding.contains(path):
            patch_review_binding.verify_path(path)
            continue
        if path == Path(__file__).absolute():
            continue
        if enumerated_identity is None:
            raise _DeveloperPathScanError()
        key = enumerated_identity[:2]
        if key in ordinary_binding.contents:
            try:
                _validate_bound_path_chain(path)
                current = path.lstat()
            except (OSError, RuntimeError, TypeError, ValueError):
                raise _DeveloperPathScanError() from None
            identity = _filesystem_identity(current)
            if _ordinary_entry_kind(current) != "regular" or identity != enumerated_identity:
                raise _DeveloperPathScanError()
            raw = ordinary_binding.add_alias(path, identity)
        else:
            unique_bytes += enumerated_identity[2]
            if unique_bytes > MAX_ORDINARY_SCAN_TOTAL_BYTES:
                raise _DeveloperPathScanError()
            try:
                raw, identity = _read_bound_regular_file(
                    path,
                    MAX_ORDINARY_SCAN_BYTES,
                    require_single_link=False,
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                raise _DeveloperPathScanError() from None
            if identity != enumerated_identity:
                raise _DeveloperPathScanError()
            ordinary_binding.add(path, raw, identity)
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for value in forbidden:
            if value in content:
                errors.append(f"{path.relative_to(ROOT)}: contains developer path {value}")
    return errors, ordinary_binding


def _unbound_developer_path_scan() -> list[str]:
    try:
        errors, binding = _scan_developer_paths(None, None, None)
        binding.revalidate()
    except _DeveloperPathScanError:
        return [DEVELOPER_PATH_VALIDATION_ERROR]
    return errors


def _validate_with_patch_review_binding(
    source_binding: object,
    patch_review_binding: _PatchReviewBinding,
) -> list[str]:
    generated_binding, generated_errors = (
        _validated_macwin_generated_evidence_binding(
            source_binding, patch_review_binding
        )
    )
    if generated_binding is None:
        try:
            scanned_errors, ordinary_binding = _scan_developer_paths(
                source_binding, None, patch_review_binding
            )
            source_binding.revalidate()
            ordinary_binding.revalidate()
            source_binding.revalidate()
            patch_review_binding.revalidate()
        except _DeveloperPathScanError:
            return [*generated_errors, DEVELOPER_PATH_VALIDATION_ERROR]
        except (OSError, RuntimeError, TypeError, ValueError):
            return [
                "Mac-Win source pack validation failed",
                *generated_errors,
                *_unbound_developer_path_scan(),
            ]
        return [*generated_errors, *scanned_errors]
    try:
        scanned_errors, ordinary_binding = _scan_developer_paths(
            source_binding, generated_binding, patch_review_binding
        )
    except _DeveloperPathScanError:
        return [DEVELOPER_PATH_VALIDATION_ERROR]
    except (OSError, RuntimeError, TypeError, ValueError):
        try:
            source_binding.revalidate()
        except (OSError, RuntimeError, TypeError, ValueError):
            return [
                "Mac-Win source pack validation failed",
                "Mac-Win generated evidence validation failed",
                *_unbound_developer_path_scan(),
            ]
        return [
            "Mac-Win generated evidence validation failed",
            *_unbound_developer_path_scan(),
        ]
    try:
        ordinary_binding.revalidate()
    except _DeveloperPathScanError:
        return [DEVELOPER_PATH_VALIDATION_ERROR]
    try:
        source_binding.revalidate()
    except (OSError, RuntimeError, TypeError, ValueError):
        return [
            "Mac-Win source pack validation failed",
            *_unbound_developer_path_scan(),
        ]
    try:
        patch_review_binding.revalidate()
    except (OSError, RuntimeError, TypeError, ValueError):
        return [
            "Mac-Win patch review evidence validation failed",
            *_unbound_developer_path_scan(),
        ]
    try:
        generated_binding.revalidate()
    except (OSError, RuntimeError, TypeError, ValueError):
        return [
            "Mac-Win generated evidence validation failed",
            *_unbound_developer_path_scan(),
        ]
    try:
        source_binding.revalidate()
    except (OSError, RuntimeError, TypeError, ValueError):
        return [
            "Mac-Win source pack validation failed",
            *_unbound_developer_path_scan(),
        ]
    try:
        ordinary_binding.revalidate()
    except _DeveloperPathScanError:
        return [DEVELOPER_PATH_VALIDATION_ERROR]
    try:
        patch_review_binding.revalidate()
    except (OSError, RuntimeError, TypeError, ValueError):
        return [
            "Mac-Win patch review evidence validation failed",
            *_unbound_developer_path_scan(),
        ]
    return scanned_errors


def validate_no_developer_paths() -> list[str]:
    source_binding, errors = _validated_macwin_source_pack_binding()
    if source_binding is None:
        return [*errors, *_unbound_developer_path_scan()]
    patch_review_binding, patch_review_errors = _validated_patch_review_binding()
    if patch_review_binding is None:
        try:
            scanned_errors, ordinary_binding = _scan_developer_paths(
                source_binding, None, None
            )
            source_binding.revalidate()
            ordinary_binding.revalidate()
            source_binding.revalidate()
        except (_DeveloperPathScanError, OSError, RuntimeError, TypeError, ValueError):
            return [*patch_review_errors, DEVELOPER_PATH_VALIDATION_ERROR]
        return [*patch_review_errors, *scanned_errors]
    try:
        return _validate_with_patch_review_binding(
            source_binding, patch_review_binding
        )
    finally:
        patch_review_binding.close()


def validate_pe_inspection_fixture() -> list[str]:
    fixture = ROOT / "tests/fixtures/hello-x86_64.exe"
    example = ROOT / "examples/executable-inspection.hello-x86_64.json"
    try:
        fixture_bytes = fixture.read_bytes()
        report = json.loads(example.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"PE inspection fixture: {error}"]

    digest = "sha256:" + hashlib.sha256(fixture_bytes).hexdigest()
    errors: list[str] = []
    if report.get("fileDigest") != digest:
        errors.append("PE inspection example digest does not match the fixture")
    if report.get("fileSizeBytes") != len(fixture_bytes):
        errors.append("PE inspection example size does not match the fixture")
    if report.get("schemaVersion") != "1":
        errors.append("PE inspection example must use Schema v1")
    imports = report.get("importLibraries")
    if not isinstance(imports, list) or not all(
        isinstance(item, str) for item in imports
    ):
        errors.append("PE inspection imports must be a string array")
    elif imports != sorted(set(imports)):
        errors.append("PE inspection imports must be canonical, sorted and unique")
    return errors


def validate_macos_preview_binary_hygiene() -> list[str]:
    allowed = {PurePosixPath("tests/fixtures/hello-x86_64.exe")}
    errors: list[str] = []
    try:
        executable_paths = sorted(ROOT.rglob("*.exe"))
    except OSError as error:
        return [f"macOS preview binary hygiene: {error}"]
    for path in executable_paths:
        if ".git" in path.parts:
            continue
        relative = PurePosixPath(path.relative_to(ROOT).as_posix())
        if relative not in allowed:
            errors.append(f"{relative}: generated Windows executable must not be stored in the repository")
    probe_source = ROOT / "tests" / "fixtures" / "windows_console_smoke.c"
    try:
        source = probe_source.read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"macOS preview probe source: {error}")
    else:
        if "COMPATFORGE_WINDOWS_CONSOLE_OK" not in source:
            errors.append("macOS preview probe source is missing its success marker")

    discovery_tool = ROOT / "tools" / "discover_macos_wine.py"
    try:
        discovery_source = discovery_tool.read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"macOS Wine discovery tool: {error}")
    else:
        for required in (
            "CrossOver.app",
            "Whisky.app",
            "Mac-Win",
            "macho_architectures",
            '"--version"',
        ):
            if required not in discovery_source:
                errors.append(f"macOS Wine discovery tool is missing bounded evidence: {required}")
        for forbidden in (
            "shutil.which",
            "shell=True",
            "os.walk",
            "Path.rglob",
            "urllib",
            "requests",
        ):
            if forbidden in discovery_source:
                errors.append(f"macOS Wine discovery tool uses forbidden discovery surface: {forbidden}")
    return errors


def _macos_acceptance_closed_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, nested in pairs:
        if not isinstance(key, str) or not key or key in value:
            raise ValueError("macOS acceptance JSON contains an invalid or duplicate key")
        value[key] = nested
    return value


def _macos_acceptance_reject_constant(_constant: str) -> object:
    raise ValueError("macOS acceptance JSON contains a non-finite value")


def _macos_acceptance_bounded_json(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > 256 or depth > 8:
            raise ValueError("macOS acceptance JSON exceeds its structural bound")
        if isinstance(current, dict):
            stack.extend((nested, depth + 1) for nested in current.values())
        elif isinstance(current, list):
            stack.extend((nested, depth + 1) for nested in current)
        elif isinstance(current, str):
            if (
                not current
                or len(current) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in current)
            ):
                raise ValueError("macOS acceptance JSON contains invalid text")
        elif current is not True and current is not False:
            raise ValueError("macOS acceptance JSON contains an unsupported scalar")


def _macos_acceptance_text(relative: str, maximum: int) -> str:
    raw, _identity = _read_bound_regular_file(ROOT / relative, maximum)
    try:
        source = raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{relative} is not UTF-8") from error
    if "\r" in source or "\x00" in source:
        raise ValueError(f"{relative} contains non-canonical text")
    return source


def _macos_acceptance_markdown(relative: str) -> str:
    source = _macos_acceptance_text(relative, MACOS_ACCEPTANCE_MAX_MARKDOWN_BYTES)
    visible = re.sub(r"(?s)<!--.*?-->", "", source)
    if "<!--" in visible:
        raise ValueError(f"{relative} contains an unclosed Markdown comment")
    return visible


def _macos_acceptance_fences(source: str) -> tuple[tuple[str, ...], ...]:
    blocks = re.findall(r"(?ms)^```text\n(.*?)\n```[ \t]*$", source)
    return tuple(tuple(block.splitlines()) for block in blocks)


def _macos_acceptance_guide_fences(
    source: str,
) -> tuple[tuple[tuple[str, ...], ...], str]:
    allowed_languages = {"", "text", "bash", "sh", "zsh", "console"}
    blocks: list[tuple[str, ...]] = []
    prose: list[str] = []
    body: list[str] | None = None
    marker_size = 0
    for line in source.splitlines():
        if body is None:
            opening = re.fullmatch(r"(?P<marker>`{3,})(?P<info>[^`]*)", line)
            if opening is None:
                if line.lstrip().startswith("```"):
                    raise ValueError("macOS acceptance guide contains an invalid fence")
                prose.append(line)
                continue
            language = opening.group("info").strip().casefold()
            if language not in allowed_languages:
                raise ValueError("macOS acceptance guide uses an unsupported fence language")
            marker_size = len(opening.group("marker"))
            body = []
            continue
        if re.fullmatch(rf"`{{{marker_size},}}[ \t]*", line):
            blocks.append(tuple(body))
            body = None
            marker_size = 0
        else:
            body.append(line)
    if body is not None:
        raise ValueError("macOS acceptance guide contains an unclosed fence")
    return tuple(blocks), "\n".join(prose)


def _macos_acceptance_prose(source: str) -> str:
    return re.sub(r"(?ms)^```[^\n]*\n.*?^```[ \t]*$", "", source)


def _macos_acceptance_semantic_text(prose: str) -> str:
    normalized = unicodedata.normalize("NFKC", prose).casefold()
    normalized = re.sub(r"[^\w]+", " ", normalized, flags=re.UNICODE)
    negated = (
        r"\b(?:this|it|compatforge|stage|gate|build|application|app)?\s*"
        r"(?:is|are|was|were)\s+not\s+(?:a\s+)?public\s+(?:beta|release)"
        r"(?:\s+ready)?(?:\s+or\s+public\s+(?:beta|release)(?:\s+ready)?)*\b",
        r"\bnot\s+(?:a\s+)?public\s+(?:beta|release)(?:\s+ready)?"
        r"(?:\s+or\s+public\s+(?:beta|release)(?:\s+ready)?)*\b",
        r"\b(?:application|app|build|artifact|binary|package|this|it)?\s*"
        r"(?:is|are|was|were)\s+not\s+(?:signed|notarized)\b",
        r"\bnot\s+(?:signed|notarized)\b",
        r"\bdoes\s+not\s+(?:create|build|ship|publish|release|distribute|provide|deliver)"
        r"\s+(?:a\s+)?dmg\b",
        r"不\s*(?:是|进入|构成|属于)\s*(?:public\s+(?:beta|release)|公测|公开测试|公开发布)"
        r"(?:\s+public\s+(?:beta|release))*",
        r"(?:未|不)\s*(?:签名|notarize|notarized|(?:完成\s*)?公证)",
        r"(?:未|不)\s*(?:公开\s*)?发布",
        r"不\s*(?:生成|创建|构建|发布|分发|交付|提供)"
        r"(?:\s*或\s*(?:生成|创建|构建|发布|分发|交付|提供))*\s*dmg",
        r"不\s*(?:允许|授权|可以|会|将)?\s*修改\s*(?:forgeos|forgetools|mac\s+win)",
    )
    for pattern in negated:
        normalized = re.sub(pattern, " ", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def _validate_macos_acceptance_nonclaims(prose: str) -> None:
    lines = prose.splitlines()
    selected = tuple(
        line
        for line in lines
        if line.startswith(("- `scope`:", "- `distribution`:", "- `coverage`:", "- `repositories`:"))
    )
    if selected != MACOS_ACCEPTANCE_NONCLAIMS:
        raise ValueError("macOS acceptance closed non-claims drifted")

    semantic = _macos_acceptance_semantic_text(prose)
    forbidden = (
        r"\bpublic\s+(?:beta|release)\b",
        r"(?:公测|公开测试|公开发布)",
        r"\bready\s+for\s+(?:a\s+)?public\s+(?:beta|release)\b",
        r"\b(?:this|it|compatforge|stage|gate|build|application|app|artifact|package)"
        r"\s+(?:is|are|was|were|will\s+be|has\s+been)\s+released\b",
        r"\b(?:application|app|build|artifact|binary|package|this|it)"
        r"\s+(?:is|are|was|were|will\s+be|has\s+been)\s+(?:signed|notarized)\b",
        r"\b(?:a\s+)?dmg\s+(?:is\s+)?ready\b",
        r"\b(?:create|creates|created|build|builds|built|ship|ships|publish|publishes|"
        r"release|releases|distribute|distributes|provide|provides|deliver|delivers)"
        r"\s+(?:a\s+)?dmg\b",
        r"\bauthorized\s+to\s+modify\s+(?:forgeos|forgetools|mac\s+win)\b",
        r"\b(?:modifications?\s+to\s+)?(?:forgeos|forgetools|mac\s+win)\s+"
        r"modifications?\s+(?:are|is)\s+authorized\b",
        r"\bmodifications?\s+to\s+(?:forgeos|forgetools|mac\s+win)\s+"
        r"(?:are|is)\s+authorized\b",
        r"\b(?:may|can|will|allowed\s+to|authorized\s+to)\s+modify\s+"
        r"(?:forgeos|forgetools|mac\s+win)\b",
        r"(?<!不)(?:是|进入|达到|构成|属于)\s*(?:public\s+(?:beta|release)|公测|公开测试|公开发布)",
        r"公开\s*发布",
        r"(?<!不)(?:已|已经|将|会|允许|可以|授权|完成)\s*(?:应用|构建|代码)?\s*"
        r"(?:签名|notarize|notarized|公证)",
        r"(?<!不)(?:生成|创建|构建|发布|分发|交付|提供|将\s*生成)\s*(?:一个)?\s*dmg",
        r"(?<!不)(?:允许|授权|可以|将|会|需要)\s*(?:直接)?\s*修改\s*"
        r"(?:forgeos|forgetools|mac\s+win)",
    )
    if any(re.search(pattern, semantic) for pattern in forbidden):
        raise ValueError("macOS acceptance guide contains a contradictory claim")


def _validate_macos_acceptance_guide(source: str) -> None:
    fences, prose = _macos_acceptance_guide_fences(source)
    headings = tuple(
        line
        for line in prose.splitlines()
        if line.startswith("#")
    )
    required_headings = (
        "# Apple Silicon 双 Runtime 本地验收",
        "## 1. 前置检查",
        "## 2. 外部根与清理边界",
        "## 3. 先构建与运行离线门禁",
        "## 4. 发现一次双 Runtime",
        "## 5. 显式 opt-in 获取固定资产",
        "## 6. 独立准备交互确认",
        "## 7. 执行两轮矩阵",
        "## 8. 负向隔离检查",
        "## 9. 精确退出门禁",
        "## 10. 闭集非声明",
    )
    if headings != required_headings:
        raise ValueError("macOS acceptance guide headings drifted")

    for marker in (
        "Python 3.11+",
        "Apple Silicon `arm64`",
        "Rosetta",
        "CrossOver",
        "Whisky",
        "x86_64-w64-mingw32-gcc",
        "Rust stable",
        "Node.js 24",
        "足够空间",
        "默认禁用网络",
        "16 paths",
        "zero cleanup failure",
        "它不是 public beta",
        "不修改 ForgeOS、ForgeTools 或 Mac-Win",
        "Screenshots、安装器、Bottle、Runtime 内容",
        "重新运行必须选择新的空",
    ):
        if prose.count(marker) < 1:
            raise ValueError(f"macOS acceptance guide marker drifted: {marker}")
    _validate_macos_acceptance_nonclaims(prose)
    for line in prose.splitlines():
        if re.match(
            r"^\s*(?:python3|cargo|npm|node|rustc|rustup|uname|arch|"
            r"test\s+-x|df\s+-h|curl|wget|sudo|softwareupdate|env|rm|cp|mv|bash|sh|zsh|"
            r"CARGO_NET_OFFLINE=|--allow-network)\b",
            line,
            flags=re.IGNORECASE,
        ):
            raise ValueError("macOS acceptance guide contains an unfenced command")
    if any(
        "curl" in line or "http://" in line or "https://" in line
        for block in fences
        for line in block
    ):
        raise ValueError("macOS acceptance guide permits an arbitrary download surface")
    if fences != MACOS_ACCEPTANCE_GUIDE_BLOCKS:
        raise ValueError("macOS acceptance guide command contract drifted")
    network_lines = tuple(
        line for block in fences for line in block if "--allow-network" in line
    )
    if network_lines != (
        *MACOS_ACCEPTANCE_ASSET_FETCH_COMMANDS,
        "  --allow-network",
    ):
        raise ValueError("macOS acceptance network opt-in escaped the fixed asset stage")


def _validate_macos_acceptance_example(source: str) -> None:
    try:
        document = json.loads(
            source,
            object_pairs_hook=_macos_acceptance_closed_object,
            parse_constant=_macos_acceptance_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeError) as error:
        raise ValueError("macOS acceptance interaction example is invalid JSON") from error
    _macos_acceptance_bounded_json(document)
    if not isinstance(document, dict) or set(document) != {"schemaVersion", "records"}:
        raise ValueError("macOS acceptance interaction example is not closed")
    if document["schemaVersion"] != "1" or not isinstance(document["records"], list):
        raise ValueError("macOS acceptance interaction example schema drifted")
    records = document["records"]
    if len(records) != len(MACOS_ACCEPTANCE_RECORDS):
        raise ValueError("macOS acceptance interaction records are incomplete")
    for record, (round_id, runtime_id) in zip(records, MACOS_ACCEPTANCE_RECORDS):
        if not isinstance(record, dict) or set(record) != {
            "confirmationId",
            "document",
            "evidencePath",
            "roundId",
            "runtimeId",
        }:
            raise ValueError("macOS acceptance interaction record is not closed")
        if record["roundId"] != round_id or record["runtimeId"] != runtime_id:
            raise ValueError("macOS acceptance interaction identity drifted")
        if record["confirmationId"] != f"{round_id}-{runtime_id}-operator-confirmation":
            raise ValueError("macOS acceptance confirmation identity drifted")
        if record["evidencePath"] != f"{round_id}/{runtime_id}.json":
            raise ValueError("macOS acceptance interaction path is not fixed and relative")
        evidence = record["document"]
        if (
            not isinstance(evidence, dict)
            or set(evidence) != {"schemaVersion", "applications"}
            or evidence["schemaVersion"] != "1"
            or not isinstance(evidence["applications"], dict)
            or set(evidence["applications"]) != set(MACOS_ACCEPTANCE_INTERACTION_CHECKS)
        ):
            raise ValueError("macOS acceptance runner document is not closed")
        for application_id, expected_checks in MACOS_ACCEPTANCE_INTERACTION_CHECKS.items():
            checks = evidence["applications"][application_id]
            if (
                not isinstance(checks, dict)
                or set(checks) != expected_checks
                or any(value is not True for value in checks.values())
            ):
                raise ValueError("macOS acceptance interaction checks drifted")
    canonical = json.dumps(
        document, ensure_ascii=False, sort_keys=True, indent=2
    ) + "\n"
    if source != canonical:
        raise ValueError("macOS acceptance interaction example is not canonical")


def validate_macos_acceptance_docs() -> list[str]:
    """Validate the closed local-only guide, navigation and interaction template."""

    try:
        guide = _macos_acceptance_markdown(MACOS_ACCEPTANCE_GUIDE)
        readme = _macos_acceptance_markdown("README.md")
        testing = _macos_acceptance_markdown("docs/testing.md")
        example = _macos_acceptance_text(
            MACOS_ACCEPTANCE_INTERACTIONS, MACOS_ACCEPTANCE_MAX_JSON_BYTES
        )
        _validate_macos_acceptance_guide(guide)
        _validate_macos_acceptance_example(example)
        readme_marker = (
            "[Apple Silicon 双 Runtime 本地验收指南]"
            "(docs/guides/macos-local-dual-runtime-acceptance.md)"
        )
        testing_marker = (
            "[双 Runtime 本地验收指南]"
            "(guides/macos-local-dual-runtime-acceptance.md)"
        )
        readme_prose = _macos_acceptance_prose(readme)
        testing_prose = _macos_acceptance_prose(testing)
        testing_fences = _macos_acceptance_fences(testing)
        if (
            readme_prose.count(readme_marker) != 1
            or testing_prose.count(testing_marker) != 1
        ):
            raise ValueError("macOS acceptance navigation marker drifted")
        if (
            "## Apple Silicon 双 Runtime developer-local 门禁" not in testing_prose
            or not any(
                "python3 -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v"
                in block
                for block in testing_fences
            )
            or "默认 CI 不下载或运行 CrossOver、Whisky、安装器或真实 Windows 应用。"
            not in testing_prose
            or "默认 CI 下载并运行" in testing_prose
        ):
            raise ValueError("macOS acceptance testing marker drifted")
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        return [f"macOS acceptance documentation validation failed: {error}"]
    return []


def validate_macos_acceptance_surface() -> list[str]:
    """Require every explicitly reviewed local acceptance entry to be regular."""

    errors: list[str] = []
    for relative in MACOS_ACCEPTANCE_REVIEWED_PATHS:
        parts = PurePosixPath(relative).parts
        path = ROOT
        try:
            for index, part in enumerate((None, *parts)):
                if part is not None:
                    path = path / part
                metadata = path.lstat()
                is_leaf = index == len(parts)
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_reparse_tag", 0)
                    or (
                        not is_leaf
                        and not stat.S_ISDIR(metadata.st_mode)
                    )
                ):
                    raise ValueError("unsafe path component")
        except OSError as error:
            errors.append(f"macOS acceptance surface {relative}: {error}")
            continue
        except ValueError:
            errors.append(
                f"macOS acceptance surface {relative}: unsafe path component"
            )
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            errors.append(
                f"macOS acceptance surface {relative}: expected a regular no-follow file"
            )
    return errors


def main() -> int:
    errors = (
        validate_macwin_asset_migration()
        + validate_bottle_migration_repository()
        + validate_json()
        + validate_workspace_members()
        + validate_markdown_links()
        + validate_no_developer_paths()
        + validate_pe_inspection_fixture()
        + validate_macos_preview_binary_hygiene()
        + validate_macos_acceptance_surface()
        + validate_macos_acceptance_docs()
    )
    if errors:
        print("repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("repository contracts are internally consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
