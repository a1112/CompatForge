#!/usr/bin/env python3
"""Materialize a hash-bound macOS Wine Runtime with an addressable app identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_IDS = ("crossover", "whisky")
BUNDLE_IDS = {
    "crossover": "dev.compatforge.acceptance.crossover",
    "whisky": "dev.compatforge.acceptance.whisky",
}
MAX_VERSION_CHARS = 128


class PreparationError(Exception):
    pass


def absolute(value: str, field: str, *, external: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute() or any(part in ("", ".", "..") for part in path.parts[1:]):
        raise PreparationError(f"{field} must be an absolute non-traversing path")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise PreparationError(f"{field} could not be resolved") from error
    if external and (resolved == ROOT or ROOT in resolved.parents):
        raise PreparationError(f"{field} must be outside the repository")
    return resolved


def relative_entrypoint(value: str, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PreparationError(f"{field} must be a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise PreparationError(f"{field} must be a portable relative path")
    return path


def regular_executable(path: Path, field: str) -> None:
    try:
        metadata = path.stat()
    except OSError as error:
        raise PreparationError(f"{field} is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        raise PreparationError(f"{field} must be a regular executable")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise PreparationError("Runtime input could not be hashed") from error
    return digest.hexdigest()


def c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def shell_string(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def write_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(mode)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    value.add_argument("--runtime-id", required=True, choices=RUNTIME_IDS)
    value.add_argument("--source-root", required=True)
    value.add_argument("--wine", required=True)
    value.add_argument("--wineserver", required=True)
    value.add_argument("--version", required=True)
    value.add_argument("--output-root", required=True)
    value.add_argument("--cc", required=True)
    return value


def validate_version(value: str) -> str:
    if (
        not value
        or len(value) > MAX_VERSION_CHARS
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+() -]*", value) is None
    ):
        raise PreparationError("version is invalid")
    return value


def clone_runtime(source: Path, destination: Path) -> None:
    result = subprocess.run(
        ["/usr/bin/ditto", "--clone", str(source), str(destination)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=20 * 60,
    )
    if result.returncode != 0:
        raise PreparationError("Runtime clone failed")


def app_plist(runtime_id: str, executable: str, version: str) -> str:
    bundle_id = BUNDLE_IDS[runtime_id]
    display_name = f"CompatForge {runtime_id.title()} Acceptance"
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>{display_name}</string>
  <key>CFBundleExecutable</key><string>{executable}</string>
  <key>CFBundleIdentifier</key><string>{bundle_id}</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>{display_name}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>{version}</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSBackgroundOnly</key><false/>
  <key>LSUIElement</key><false/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
'''


def observer_launcher_source(wine: Path, wineserver: Path) -> str:
    values = {
        "wine": c_string(str(wine)),
        "wineserver": c_string(str(wineserver)),
    }
    return r'''#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const char *wine = %(wine)s;
static const char *wineserver = %(wineserver)s;

static int receive_descriptor(const char *path)
{
    struct sockaddr_un address;
    if (!path || !*path || strlen(path) >= sizeof(address.sun_path)) return -1;
    int socket_descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_descriptor < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(socket_descriptor, (struct sockaddr *)&address, sizeof(address)) != 0)
    { close(socket_descriptor); return -1; }
    char byte = 0;
    struct iovec vector = { .iov_base = &byte, .iov_len = 1 };
    union { struct cmsghdr header; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    if (recvmsg(socket_descriptor, &message, 0) != 1)
    { close(socket_descriptor); return -1; }
    close(socket_descriptor);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    int descriptor = -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    if (descriptor < 3 || fcntl(descriptor, F_SETFD, 0) != 0)
    { if (descriptor >= 0) close(descriptor); return -1; }
    return descriptor;
}

int main(int argc, char **argv)
{
    if (setenv("WINESERVER", wineserver, 1) != 0) return 125;
    if (argc > 3 && strcmp(argv[1], "--compatforge-receive-fd") == 0)
    {
        int descriptor = receive_descriptor(argv[2]);
        if (descriptor < 0)
        { fputs("compatforge descriptor transfer failed\n", stderr); return 125; }
        const char *guest_path = argv[3];
        if (!guest_path || guest_path[0] != '/' || strstr(guest_path, "/../") ||
            strstr(guest_path, "/./"))
            return 125;
        char descriptor_path[64];
        if (snprintf(descriptor_path, sizeof(descriptor_path), "/dev/fd/%%d", descriptor) >=
            (int)sizeof(descriptor_path)) return 125;
        if (symlink(descriptor_path, guest_path) != 0) return 125;
        argv[0] = (char *)wine;
        argv[1] = guest_path;
        for (int index = 4; index < argc; ++index) argv[index - 2] = argv[index];
        argv[argc - 2] = NULL;
        execv(wine, argv);
        return 126;
    }
    argv[0] = (char *)wine;
    execv(wine, argv);
    return 126;
}
''' % values


def launcher_source(
    wine: Path,
    app: Path,
    app_executable: Path,
    info_plist: Path,
    expected_wine: str,
    expected_app_executable: str,
    expected_info_plist: str,
) -> str:
    values = {
        "wine": c_string(str(wine)),
        "app": c_string(str(app)),
        "app_executable": c_string(str(app_executable)),
        "info_plist": c_string(str(info_plist)),
        "expected_wine": c_string(expected_wine),
        "expected_app_executable": c_string(expected_app_executable),
        "expected_info_plist": c_string(expected_info_plist),
    }
    return r'''#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *wine = %(wine)s;
static const char *app = %(app)s;
static const char *app_executable = %(app_executable)s;
static const char *info_plist = %(info_plist)s;
static const char *expected_wine = %(expected_wine)s;
static const char *expected_app_executable = %(expected_app_executable)s;
static const char *expected_info_plist = %(expected_info_plist)s;

static int matches_sha256(const char *path, const char *expected)
{
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    char hex[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    CC_SHA256_CTX context;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || CC_SHA256_Init(&context) != 1) return 0;
    for (;;)
    {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));
        if (count < 0) { close(descriptor); return 0; }
        if (count == 0) break;
        if (CC_SHA256_Update(&context, buffer, (CC_LONG)count) != 1)
        { close(descriptor); return 0; }
    }
    close(descriptor);
    if (CC_SHA256_Final(digest, &context) != 1) return 0;
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i)
        snprintf(hex + i * 2, 3, "%%02x", digest[i]);
    return strcmp(hex, expected) == 0;
}

static int is_console_guest(const char *path)
{
    unsigned char header[2], offset_bytes[4], signature[4], subsystem[2];
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return 0;
    if (pread(descriptor, header, 2, 0) != 2 || header[0] != 'M' || header[1] != 'Z' ||
        pread(descriptor, offset_bytes, 4, 0x3c) != 4)
    { close(descriptor); return 0; }
    uint32_t pe = (uint32_t)offset_bytes[0] | ((uint32_t)offset_bytes[1] << 8) |
                  ((uint32_t)offset_bytes[2] << 16) | ((uint32_t)offset_bytes[3] << 24);
    if (pe > 16 * 1024 * 1024 || pread(descriptor, signature, 4, pe) != 4 ||
        memcmp(signature, "PE\0\0", 4) != 0 ||
        pread(descriptor, subsystem, 2, (off_t)pe + 24 + 68) != 2)
    { close(descriptor); return 0; }
    close(descriptor);
    return ((unsigned)subsystem[0] | ((unsigned)subsystem[1] << 8)) == 3;
}

static int is_inherited_descriptor_guest(const char *path)
{
    static const char prefix[] = "/dev/fd/";
    if (strncmp(path, prefix, sizeof(prefix) - 1) != 0) return 0;
    const char *digits = path + sizeof(prefix) - 1;
    if (*digits < '1' || *digits > '9') return 0;
    unsigned long value = 0;
    for (const char *cursor = digits; *cursor; ++cursor)
    {
        if (*cursor < '0' || *cursor > '9') return 0;
        value = value * 10 + (unsigned long)(*cursor - '0');
        if (value > 2147483647UL) return 0;
    }
    return value > 2;
}

static int inherited_descriptor(const char *path)
{
    if (!is_inherited_descriptor_guest(path)) return -1;
    return atoi(path + strlen("/dev/fd/"));
}

static volatile sig_atomic_t termination_signal = 0;

static void remember_termination_signal(int signal_number)
{
    termination_signal = signal_number;
}

static int cleanup_owned_directory(const char *path)
{
    DIR *stream = opendir(path);
    if (!stream) return rmdir(path) == 0;
    int descriptor = dirfd(stream);
    int complete = descriptor >= 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (descriptor < 0 || unlinkat(descriptor, entry->d_name, 0) != 0)
            complete = 0;
    }
    if (closedir(stream) != 0) complete = 0;
    if (rmdir(path) != 0) complete = 0;
    return complete;
}

static int launch_inherited_descriptor_guest(int argc, char **argv)
{
    int guest_descriptor = inherited_descriptor(argv[1]);
    if (guest_descriptor < 3 || fcntl(guest_descriptor, F_GETFD) < 0) return 125;
    const char *guest_name = "SumatraPDF.exe";
    char directory[] = "/private/tmp/compatforge-wine-fd-XXXXXXXXXXXX";
    if (!mkdtemp(directory)) return 125;
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    if (snprintf(socket_path, sizeof(socket_path), "%%s/broker.sock", directory) >=
        (int)sizeof(socket_path)) { rmdir(directory); return 125; }
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) { rmdir(directory); return 125; }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0)
    { close(listener); unlink(socket_path); rmdir(directory); return 125; }

    const char *prefix = getenv("WINEPREFIX");
    const char *debug = getenv("WINEDEBUG");
    if (!prefix || !*prefix) { close(listener); unlink(socket_path); rmdir(directory); return 125; }
    if (!debug || !*debug) debug = "-all";
    char guest_directory[4096];
    if (snprintf(
            guest_directory,
            sizeof(guest_directory),
            "%%s/drive_c/windows/temp/compatforge-pinned-XXXXXXXXXXXX",
            prefix
        ) >= (int)sizeof(guest_directory) || !mkdtemp(guest_directory))
    { close(listener); unlink(socket_path); rmdir(directory); return 125; }
    char guest_link[4096];
    if (snprintf(guest_link, sizeof(guest_link), "%%s/%%s", guest_directory, guest_name) >=
        (int)sizeof(guest_link))
    {
        close(listener);
        unlink(socket_path);
        rmdir(directory);
        cleanup_owned_directory(guest_directory);
        return 125;
    }
    char prefix_env[4096], debug_env[512];
    if (snprintf(prefix_env, sizeof(prefix_env), "WINEPREFIX=%%s", prefix) >= (int)sizeof(prefix_env) ||
        snprintf(debug_env, sizeof(debug_env), "WINEDEBUG=%%s", debug) >= (int)sizeof(debug_env))
    { close(listener); unlink(socket_path); rmdir(directory); return 125; }
    char **open_argv = calloc((size_t)argc + 14, sizeof(char *));
    if (!open_argv)
    {
        close(listener);
        unlink(socket_path);
        rmdir(directory);
        cleanup_owned_directory(guest_directory);
        return 125;
    }
    int index = 0;
    open_argv[index++] = "/usr/bin/open";
    open_argv[index++] = "-W";
    open_argv[index++] = "-n";
    open_argv[index++] = "--env";
    open_argv[index++] = prefix_env;
    open_argv[index++] = "--env";
    open_argv[index++] = debug_env;
    open_argv[index++] = (char *)app;
    open_argv[index++] = "--args";
    open_argv[index++] = "--compatforge-receive-fd";
    open_argv[index++] = socket_path;
    open_argv[index++] = guest_link;
    for (int argument = 2; argument < argc; ++argument) open_argv[index++] = argv[argument];
    open_argv[index] = NULL;

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = remember_termination_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    pid_t child = fork();
    if (child == 0)
    {
        close(listener);
        execv(open_argv[0], open_argv);
        _exit(126);
    }
    free(open_argv);
    if (child < 0)
    {
        close(listener);
        unlink(socket_path);
        rmdir(directory);
        cleanup_owned_directory(guest_directory);
        return 125;
    }
    struct pollfd ready = { .fd = listener, .events = POLLIN };
    int connected = poll(&ready, 1, 15000);
    int peer = connected > 0 ? accept(listener, NULL, NULL) : -1;
    int transfer_ok = 0;
    if (peer >= 0)
    {
        char byte = '!';
        struct iovec vector = { .iov_base = &byte, .iov_len = 1 };
        union { struct cmsghdr header; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
        memset(&control, 0, sizeof(control));
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &guest_descriptor, sizeof(guest_descriptor));
        transfer_ok = sendmsg(peer, &message, 0) == 1;
        close(peer);
    }
    close(listener);
    if (!transfer_ok)
    {
        kill(child, SIGTERM);
        waitpid(child, NULL, 0);
        cleanup_owned_directory(guest_directory);
        cleanup_owned_directory(directory);
        return 125;
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    int cleanup_ok = cleanup_owned_directory(guest_directory) &&
                     cleanup_owned_directory(directory);
    if (waited < 0) return 126;
    if (!cleanup_ok) return 125;
    if (termination_signal) return 128 + termination_signal;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 126;
}

int main(int argc, char **argv)
{
    if (!matches_sha256(wine, expected_wine) ||
        !matches_sha256(app_executable, expected_app_executable) ||
        !matches_sha256(info_plist, expected_info_plist))
    {
        fputs("compatforge interactive Runtime integrity check failed\n", stderr);
        return 125;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0)
    {
        argv[0] = (char *)wine;
        execv(wine, argv);
        return 126;
    }
    if (argc > 1 && is_console_guest(argv[1]))
    {
        argv[0] = (char *)wine;
        execv(wine, argv);
        return 126;
    }
    if (argc > 1 && is_inherited_descriptor_guest(argv[1]))
        return launch_inherited_descriptor_guest(argc, argv);
    const char *prefix = getenv("WINEPREFIX");
    const char *debug = getenv("WINEDEBUG");
    if (!prefix || !*prefix) { fputs("WINEPREFIX is required\n", stderr); return 125; }
    if (!debug || !*debug) debug = "-all";
    char prefix_env[4096], debug_env[512];
    if (snprintf(prefix_env, sizeof(prefix_env), "WINEPREFIX=%%s", prefix) >= (int)sizeof(prefix_env) ||
        snprintf(debug_env, sizeof(debug_env), "WINEDEBUG=%%s", debug) >= (int)sizeof(debug_env))
        return 125;
    char **open_argv = calloc((size_t)argc + 12, sizeof(char *));
    if (!open_argv) return 125;
    int i = 0;
    open_argv[i++] = "/usr/bin/open";
    open_argv[i++] = "-W";
    open_argv[i++] = "-n";
    open_argv[i++] = "--env";
    open_argv[i++] = prefix_env;
    open_argv[i++] = "--env";
    open_argv[i++] = debug_env;
    open_argv[i++] = (char *)app;
    open_argv[i++] = "--args";
    for (int arg = 1; arg < argc; ++arg) open_argv[i++] = argv[arg];
    open_argv[i] = NULL;
    execv(open_argv[0], open_argv);
    fprintf(stderr, "compatforge interactive Runtime launch failed: %%s\n", strerror(errno));
    return 126;
}
''' % values


def prepare(arguments: argparse.Namespace) -> dict[str, str]:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise PreparationError("interactive Runtime preparation requires Darwin/arm64")
    runtime_id = arguments.runtime_id
    source_root = absolute(arguments.source_root, "source-root")
    output_root = absolute(arguments.output_root, "output-root", external=True)
    cc = absolute(arguments.cc, "cc")
    wine_relative = relative_entrypoint(arguments.wine, "wine")
    wineserver_relative = relative_entrypoint(arguments.wineserver, "wineserver")
    version = validate_version(arguments.version)
    if not source_root.is_dir() or output_root.exists():
        raise PreparationError("source-root must exist and output-root must not exist")
    regular_executable(cc, "cc")
    source_wine = source_root.joinpath(*wine_relative.parts).resolve(strict=True)
    source_wineserver = source_root.joinpath(*wineserver_relative.parts).resolve(strict=True)
    if source_root not in source_wine.parents or source_root not in source_wineserver.parents:
        raise PreparationError("Runtime entrypoint escapes source-root")
    regular_executable(source_wine, "wine")
    regular_executable(source_wineserver, "wineserver")

    output_root.parent.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(mode=0o700)
    runtime_root = output_root / "runtime"
    try:
        clone_runtime(source_root, runtime_root)
        wine = runtime_root.joinpath(*wine_relative.parts).resolve(strict=True)
        wineserver = runtime_root.joinpath(*wineserver_relative.parts).resolve(strict=True)
        if runtime_root not in wine.parents or runtime_root not in wineserver.parents:
            raise PreparationError("cloned Runtime entrypoint escapes materialized root")

        app_name = f"CompatForge{runtime_id.title()}Acceptance.app"
        app = output_root / "observer" / app_name
        app_executable = app / "Contents" / "MacOS" / "wineloader"
        info_plist = app / "Contents" / "Info.plist"
        app_executable.parent.mkdir(parents=True, exist_ok=True)
        if runtime_id == "crossover":
            shutil.copy2(wine, app_executable)
            ntdll = wine.parent / "ntdll.so"
            if not ntdll.is_file():
                raise PreparationError("CrossOver ntdll.so is unavailable")
            os.symlink(ntdll, app_executable.parent / "ntdll.so")
        else:
            observer_c = output_root / "provenance" / "observer-launcher.c"
            write_text(observer_c, observer_launcher_source(wine, wineserver))
            compiled_observer = subprocess.run(
                [str(cc), "-arch", "x86_64", "-Os", str(observer_c), "-o", str(app_executable)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=120,
            )
            if compiled_observer.returncode != 0:
                raise PreparationError("observer launcher compilation failed")
            regular_executable(app_executable, "observer launcher")
        write_text(info_plist, app_plist(runtime_id, "wineloader", version))
        signed = subprocess.run(
            ["/usr/bin/codesign", "--force", "--deep", "--sign", "-", str(app)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=60,
        )
        if signed.returncode != 0:
            raise PreparationError("observer app signing failed")

        if runtime_id == "crossover":
            derived_wine = app_executable
        else:
            launcher_c = output_root / "provenance" / "interactive-launcher.c"
            launcher = output_root / "bin" / "wine"
            write_text(
                launcher_c,
                launcher_source(
                    wine,
                    app,
                    app_executable,
                    info_plist,
                    sha256(wine),
                    sha256(app_executable),
                    sha256(info_plist),
                ),
            )
            launcher.parent.mkdir(parents=True, exist_ok=True)
            compiled = subprocess.run(
                [str(cc), "-arch", "x86_64", "-Os", str(launcher_c), "-o", str(launcher)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=120,
            )
            if compiled.returncode != 0:
                raise PreparationError("interactive launcher compilation failed")
            regular_executable(launcher, "interactive launcher")
            derived_wine = launcher

        descriptor = {
            "architecture": "x86_64",
            "materializedRoot": str(output_root),
            "runtimeId": runtime_id,
            "schemaVersion": "1",
            "source": f"{runtime_id}-interactive-derived",
            "version": version,
            "wine": derived_wine.relative_to(output_root).as_posix(),
            "wineserver": wineserver.relative_to(output_root).as_posix(),
        }
        provenance = {
            "bundleId": BUNDLE_IDS[runtime_id],
            "derivedWineSha256": sha256(derived_wine),
            "observerExecutableSha256": sha256(app_executable),
            "observerInfoPlistSha256": sha256(info_plist),
            "runtimeId": runtime_id,
            "schemaVersion": "1",
            "sourceRoot": str(source_root),
            "sourceWineSha256": sha256(source_wine),
            "sourceWineserverSha256": sha256(source_wineserver),
            "version": version,
        }
        write_text(
            output_root / "descriptor.json",
            json.dumps(descriptor, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        )
        write_text(
            output_root / "provenance.json",
            json.dumps(provenance, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        )
        return descriptor
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def main() -> int:
    try:
        arguments = parser().parse_args()
        result = prepare(arguments)
    except (PreparationError, OSError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"compatforge-interactive-runtime: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
