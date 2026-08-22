from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools" / "confirm_macos_gui_interactions.py"
VALIDATOR = ROOT / "scripts" / "validate_repository.py"

ROUND_IDS = ("round-1", "round-2")
RUNTIME_IDS = ("crossover", "whisky")
APPLICATIONS = ("7zip", "sumatrapdf", "notepad-plus-plus")
REQUIRED_CHECKS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches"),
}


def canonical_bytes(value: object) -> bytes:
    """Independent literal oracle for the wire representation."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def literal_challenge(
    *,
    round_id: str = "round-1",
    runtime_id: str = "crossover",
    runtime_version: str = "24.0",
    app_id: str = "7zip",
    pack_digest: str = "sha256:" + "a" * 64,
    asset_digest: str = "sha256:" + "b" * 64,
    nonce: str = "c" * 64,
) -> dict[str, object]:
    return {
        "schemaVersion": "1",
        "roundId": round_id,
        "runtimeId": runtime_id,
        "runtimeVersion": runtime_version,
        "appId": app_id,
        "packDigest": pack_digest,
        "assetDigest": asset_digest,
        "requiredChecks": list(REQUIRED_CHECKS[app_id]),
        "nonce": nonce,
    }


def literal_acknowledgement(
    challenge: dict[str, object] | None = None,
) -> dict[str, object]:
    current = literal_challenge() if challenge is None else challenge
    required_checks = current["requiredChecks"]
    assert isinstance(required_checks, list)
    return {
        **current,
        "challengeDigest": "sha256:" + hashlib.sha256(
            canonical_bytes(current)
        ).hexdigest(),
        "interactionChecks": {
            check: True for check in required_checks
        },
    }


def load_helper():
    if not HELPER.is_file():
        raise AssertionError("macOS interaction acknowledgement helper is missing")
    name = "confirm_macos_gui_interactions_under_test"
    spec = importlib.util.spec_from_file_location(name, HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AcknowledgementProtocolTests(unittest.TestCase):
    helper = load_helper()

    def test_helper_exists(self) -> None:
        self.assertTrue(HELPER.is_file(), "macOS interaction acknowledgement helper is missing")

    def test_fixed_protocol_literals_and_twelve_names_are_exact(self) -> None:
        self.assertEqual(self.helper.ROUND_IDS, ROUND_IDS)
        self.assertEqual(self.helper.RUNTIME_IDS, RUNTIME_IDS)
        self.assertEqual(self.helper.APPLICATION_IDS, APPLICATIONS)
        self.assertEqual(self.helper.REQUIRED_CHECKS, REQUIRED_CHECKS)
        self.assertEqual(
            self.helper.CHALLENGE_NAMES,
            tuple(
                f"{round_id}--{runtime_id}--{app_id}.json"
                for round_id in ROUND_IDS
                for runtime_id in RUNTIME_IDS
                for app_id in APPLICATIONS
            ),
        )

    def test_challenge_and_acknowledgement_match_the_literal_canonical_oracle(self) -> None:
        challenge = literal_challenge()
        acknowledgement = literal_acknowledgement(challenge)

        self.assertEqual(self.helper.encode_challenge(challenge), canonical_bytes(challenge))
        self.assertEqual(
            self.helper.challenge_digest(challenge),
            acknowledgement["challengeDigest"],
        )
        self.assertEqual(
            self.helper.encode_acknowledgement(acknowledgement),
            canonical_bytes(acknowledgement),
        )
        self.assertEqual(
            self.helper.parse_challenge(canonical_bytes(challenge)), challenge
        )
        self.assertEqual(
            self.helper.parse_acknowledgement(canonical_bytes(acknowledgement)),
            acknowledgement,
        )
        self.assertEqual(
            self.helper.validate_acknowledgement(challenge, acknowledgement),
            acknowledgement["interactionChecks"],
        )

    def test_make_challenge_uses_only_the_injected_nonce_and_exact_identity(self) -> None:
        calls: list[int] = []

        def nonce_source(size: int) -> str:
            calls.append(size)
            return "d" * (size * 2)

        challenge = self.helper.make_challenge(
            round_id="round-2",
            runtime_id="whisky",
            runtime_version="2.3.4",
            app_id="sumatrapdf",
            pack_digest="sha256:" + "e" * 64,
            asset_digest="sha256:" + "f" * 64,
            nonce_source=nonce_source,
        )
        self.assertEqual(calls, [32])
        self.assertEqual(
            challenge,
            literal_challenge(
                round_id="round-2",
                runtime_id="whisky",
                runtime_version="2.3.4",
                app_id="sumatrapdf",
                pack_digest="sha256:" + "e" * 64,
                asset_digest="sha256:" + "f" * 64,
                nonce="d" * 64,
            ),
        )

    def test_parser_rejects_duplicate_unknown_reordered_and_noncanonical_bytes(self) -> None:
        challenge = literal_challenge()
        canonical = canonical_bytes(challenge)
        duplicate = canonical.replace(
            b'{"appId":"7zip",',
            b'{"appId":"7zip","appId":"7zip",',
            1,
        )
        unknown = {**challenge, "unknown": "value"}
        reordered = json.dumps(
            challenge, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        cases = {
            "duplicate": duplicate,
            "unknown": canonical_bytes(unknown),
            "reordered": reordered,
            "space": canonical[:-1] + b" \n",
            "missing-lf": canonical[:-1],
            "crlf": canonical[:-1] + b"\r\n",
            "escaped-ascii": canonical.replace(b'"round-1"', b'"round-\\u0031"'),
        }
        for label, raw in cases.items():
            with self.subTest(label=label), self.assertRaises(
                self.helper.AcknowledgementError
            ):
                self.helper.parse_challenge(raw)

    def test_closed_schemas_reject_wrong_types_missing_fields_and_bad_values(self) -> None:
        challenge = literal_challenge()
        acknowledgement = literal_acknowledgement(challenge)
        challenge_mutants: dict[str, dict[str, object]] = {
            "schema-type": {**challenge, "schemaVersion": 1},
            "schema-version": {**challenge, "schemaVersion": "2"},
            "round": {**challenge, "roundId": "round-3"},
            "runtime": {**challenge, "runtimeId": "wine"},
            "runtime-version-type": {**challenge, "runtimeVersion": 24},
            "runtime-version-control": {**challenge, "runtimeVersion": "24.0\n"},
            "application": {**challenge, "appId": "console"},
            "pack-prefix": {**challenge, "packDigest": "md5:" + "a" * 64},
            "pack-uppercase": {**challenge, "packDigest": "sha256:" + "A" * 64},
            "asset-short": {**challenge, "assetDigest": "sha256:" + "b" * 63},
            "nonce-short": {**challenge, "nonce": "c" * 63},
            "nonce-uppercase": {**challenge, "nonce": "C" * 64},
            "checks-type": {**challenge, "requiredChecks": tuple(REQUIRED_CHECKS["7zip"])},
            "checks-order": {**challenge, "requiredChecks": ["menus", "fileList"]},
            "checks-extra": {**challenge, "requiredChecks": ["fileList", "menus", "open"]},
            "checks-missing": {**challenge, "requiredChecks": ["fileList"]},
        }
        missing = dict(challenge)
        del missing["nonce"]
        challenge_mutants["missing"] = missing
        for label, mutant in challenge_mutants.items():
            with self.subTest(kind="challenge", label=label), self.assertRaises(
                self.helper.AcknowledgementError
            ):
                if label == "checks-type":
                    self.helper.encode_challenge(mutant)
                else:
                    self.helper.parse_challenge(canonical_bytes(mutant))

        acknowledgement_mutants: dict[str, dict[str, object]] = {
            "false": {
                **acknowledgement,
                "interactionChecks": {"fileList": True, "menus": False},
            },
            "boolean-subclass-guard": {
                **acknowledgement,
                "interactionChecks": {"fileList": 1, "menus": True},
            },
            "extra-check": {
                **acknowledgement,
                "interactionChecks": {"fileList": True, "menus": True, "open": True},
            },
            "missing-check": {
                **acknowledgement,
                "interactionChecks": {"fileList": True},
            },
            "digest": {**acknowledgement, "challengeDigest": "sha256:" + "0" * 63},
        }
        for label, mutant in acknowledgement_mutants.items():
            with self.subTest(kind="acknowledgement", label=label), self.assertRaises(
                self.helper.AcknowledgementError
            ):
                self.helper.parse_acknowledgement(canonical_bytes(mutant))

    def test_parser_rejects_oversized_deep_non_utf8_and_non_json_inputs(self) -> None:
        invalid = {
            "oversized": b" " * (self.helper.MAX_DOCUMENT_BYTES + 1),
            "deep": (b"[" * (self.helper.MAX_JSON_DEPTH + 1))
            + b"0"
            + (b"]" * (self.helper.MAX_JSON_DEPTH + 1)),
            "non-utf8": b"\xff",
            "non-json": b"not-json\n",
            "float": b"1.0\n",
            "constant": b"NaN\n",
        }
        for label, raw in invalid.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                self.helper.AcknowledgementError,
                r"^[A-Za-z][A-Za-z -]+$",
            ):
                self.helper.parse_challenge(raw)

    def test_acknowledgement_binding_rejects_every_identity_and_digest_drift(self) -> None:
        challenge = literal_challenge()
        acknowledgement = literal_acknowledgement(challenge)
        mutations = {
            "roundId": "round-2",
            "runtimeId": "whisky",
            "runtimeVersion": "24.1",
            "appId": "sumatrapdf",
            "packDigest": "sha256:" + "0" * 64,
            "assetDigest": "sha256:" + "1" * 64,
            "requiredChecks": ["menus", "fileList"],
            "nonce": "2" * 64,
            "challengeDigest": "sha256:" + "3" * 64,
        }
        for field, replacement in mutations.items():
            mutant = {**acknowledgement, field: replacement}
            if field == "appId":
                mutant["requiredChecks"] = list(REQUIRED_CHECKS["sumatrapdf"])
                mutant["interactionChecks"] = {
                    check: True for check in REQUIRED_CHECKS["sumatrapdf"]
                }
            elif field == "requiredChecks":
                mutant["interactionChecks"] = {"menus": True, "fileList": True}
            if field == "requiredChecks":
                context = self.assertRaises(self.helper.AcknowledgementError)
            else:
                context = self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^acknowledgement does not match challenge$",
                )
            with self.subTest(field=field), context:
                self.helper.validate_acknowledgement(challenge, mutant)

    def test_create_new_round_trip_rejects_existing_linked_and_hardlinked_entries(self) -> None:
        challenge = literal_challenge()
        acknowledgement = literal_acknowledgement(challenge)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            challenge_path = root / "challenge.json"
            receipt_path = root / "receipt.json"
            self.helper.write_challenge(challenge_path, challenge)
            self.helper.write_acknowledgement(receipt_path, acknowledgement)
            self.assertEqual(self.helper.read_challenge(challenge_path), challenge)
            self.assertEqual(
                self.helper.read_acknowledgement(receipt_path), acknowledgement
            )
            before = receipt_path.read_bytes()
            with self.assertRaisesRegex(
                self.helper.AcknowledgementError, "^acknowledgement file already exists$"
            ):
                self.helper.write_acknowledgement(receipt_path, acknowledgement)
            self.assertEqual(receipt_path.read_bytes(), before)

            hardlink = root / "hardlink.json"
            os.link(receipt_path, hardlink)
            with self.assertRaisesRegex(
                self.helper.AcknowledgementError, "^acknowledgement file is unsafe$"
            ):
                self.helper.read_acknowledgement(hardlink)

            symlink = root / "symlink.json"
            try:
                symlink.symlink_to(challenge_path)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(
                    self.helper.AcknowledgementError, "^challenge file is unsafe$"
                ):
                    self.helper.read_challenge(symlink)


class AcknowledgementWatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper = load_helper()

    def _challenge_for(self, index: int) -> dict[str, object]:
        round_id = ROUND_IDS[index // (len(RUNTIME_IDS) * len(APPLICATIONS))]
        runtime_index = (index // len(APPLICATIONS)) % len(RUNTIME_IDS)
        runtime_id = RUNTIME_IDS[runtime_index]
        app_id = APPLICATIONS[index % len(APPLICATIONS)]
        counter = index + 1
        return self.helper.make_challenge(
            round_id=round_id,
            runtime_id=runtime_id,
            runtime_version="24.0" if runtime_id == "crossover" else "2.3.4",
            app_id=app_id,
            pack_digest="sha256:" + format(counter, "064x"),
            asset_digest="sha256:" + format(counter + 32, "064x"),
            nonce_source=lambda size, value=counter + 64: format(value, f"0{size * 2}x"),
        )

    @staticmethod
    def _roots(directory: str) -> tuple[Path, Path, Path, Path]:
        base = Path(directory)
        plan_root = base / "plans"
        acknowledgement_root = base / "acknowledgements"
        challenges = acknowledgement_root / "challenges"
        receipts = acknowledgement_root / "receipts"
        plan_root.mkdir()
        acknowledgement_root.mkdir()
        challenges.mkdir()
        receipts.mkdir()
        return plan_root, acknowledgement_root, challenges, receipts

    def test_watch_exists(self) -> None:
        self.assertTrue(
            hasattr(self.helper, "watch"),
            "macOS interaction acknowledgement watch mode is missing",
        )

    def test_watch_handles_twelve_delayed_challenges_in_fixed_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            documents = [self._challenge_for(index) for index in range(12)]
            self.helper.write_challenge(
                challenges / self.helper.CHALLENGE_NAMES[0], documents[0]
            )
            prompted: list[str] = []
            sleep_calls: list[float] = []
            clock = [100.0]
            next_to_create = [1]

            def monotonic() -> float:
                return clock[0]

            def sleeper(seconds: float) -> None:
                self.assertGreaterEqual(seconds, self.helper.MIN_POLL_SECONDS)
                self.assertLessEqual(seconds, self.helper.MAX_POLL_SECONDS)
                sleep_calls.append(seconds)
                clock[0] += seconds
                index = next_to_create[0]
                if index < len(documents):
                    self.helper.write_challenge(
                        challenges / self.helper.CHALLENGE_NAMES[index], documents[index]
                    )
                    next_to_create[0] += 1

            def confirm(prompt: str) -> str:
                prompted.append(prompt)
                prefix = prompt.split(": confirm ", 1)[0]
                round_id, runtime_id, app_id = prefix.split(" ")
                name = f"{round_id}--{runtime_id}--{app_id}.json"
                self.assertTrue((challenges / name).is_file())
                self.assertFalse((receipts / name).exists())
                return "yes"

            completed = self.helper.watch(
                plan_root,
                acknowledgement_root,
                input_fn=confirm,
                monotonic=monotonic,
                sleeper=sleeper,
                poll_interval=0.25,
                deadline_seconds=30.0,
            )

            expected_prompts = [
                f"{challenge['roundId']} {challenge['runtimeId']} {challenge['appId']}: "
                f"confirm {check} [yes/no]: "
                for challenge in documents
                for check in challenge["requiredChecks"]
            ]
            self.assertEqual(prompted, expected_prompts)
            self.assertEqual(completed, 12)
            self.assertEqual(len(sleep_calls), 11)
            self.assertEqual(
                {path.name for path in receipts.iterdir()},
                set(self.helper.CHALLENGE_NAMES),
            )
            for index, name in enumerate(self.helper.CHALLENGE_NAMES):
                acknowledgement = self.helper.read_acknowledgement(receipts / name)
                self.assertEqual(
                    self.helper.validate_acknowledgement(
                        documents[index], acknowledgement
                    ),
                    {
                        check: True
                        for check in documents[index]["requiredChecks"]
                    },
                )

    def test_negative_and_keyboard_interrupt_write_no_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            documents = [self._challenge_for(index) for index in range(12)]
            for name, challenge in zip(self.helper.CHALLENGE_NAMES, documents):
                self.helper.write_challenge(challenges / name, challenge)
            answers = [0]

            def one_negative(_prompt: str) -> str:
                answers[0] += 1
                return "no" if answers[0] == 1 else "yes"

            with self.assertRaisesRegex(
                self.helper.AcknowledgementError,
                "^one or more interactions were not acknowledged$",
            ):
                self.helper.watch(
                    plan_root,
                    acknowledgement_root,
                    input_fn=one_negative,
                )
            self.assertFalse((receipts / self.helper.CHALLENGE_NAMES[0]).exists())
            self.assertEqual(len(tuple(receipts.iterdir())), 11)

        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            challenge = self._challenge_for(0)
            name = self.helper.CHALLENGE_NAMES[0]
            self.helper.write_challenge(challenges / name, challenge)
            calls = [0]

            def interrupted(_prompt: str) -> str:
                calls[0] += 1
                if calls[0] == 1:
                    return "yes"
                raise KeyboardInterrupt

            with self.assertRaisesRegex(
                self.helper.AcknowledgementError,
                "^operator cancelled acknowledgement$",
            ):
                self.helper.watch(
                    plan_root,
                    acknowledgement_root,
                    input_fn=interrupted,
                )
            self.assertEqual(tuple(receipts.iterdir()), ())

        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            name = self.helper.CHALLENGE_NAMES[0]
            self.helper.write_challenge(challenges / name, self._challenge_for(0))
            with self.assertRaisesRegex(
                self.helper.AcknowledgementError,
                "^operator cancelled acknowledgement$",
            ):
                self.helper.watch(
                    plan_root,
                    acknowledgement_root,
                    input_fn=lambda _prompt: "cancel",
                )
            self.assertEqual(tuple(receipts.iterdir()), ())

    def test_final_receipt_name_is_invisible_until_the_complete_file_is_synced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "receipt.json"
            acknowledgement = self.helper.make_acknowledgement(self._challenge_for(0))
            original_write = self.helper._write_all

            def observe_before_write(descriptor: int, payload: bytes) -> None:
                self.assertFalse(target.exists())
                original_write(descriptor, payload)
                self.assertFalse(target.exists())

            with mock.patch.object(self.helper, "_write_all", observe_before_write):
                self.helper.write_acknowledgement(target, acknowledgement)
            self.assertEqual(
                self.helper.read_acknowledgement(target), acknowledgement
            )

    def test_failed_directory_sync_removes_the_published_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "receipt.json"
            acknowledgement = self.helper.make_acknowledgement(self._challenge_for(0))

            with mock.patch.object(
                self.helper,
                "_sync_directory",
                side_effect=OSError("injected directory sync failure"),
            ):
                with self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^acknowledgement file could not be created safely$",
                ):
                    self.helper.write_acknowledgement(target, acknowledgement)

            self.assertFalse(target.exists())
            self.assertEqual(tuple(root.iterdir()), ())

    def test_failed_validation_unlinks_owned_final_even_when_it_was_hardlinked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "receipt.json"
            attacker_link = root / "attacker-link.json"
            acknowledgement = self.helper.make_acknowledgement(self._challenge_for(0))
            original_sync = self.helper._sync_directory

            def hardlink_after_publish(binding: object) -> None:
                original_sync(binding)
                os.link(target, attacker_link)

            with mock.patch.object(
                self.helper,
                "_sync_directory",
                side_effect=hardlink_after_publish,
            ):
                with self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^acknowledgement file identity changed$",
                ):
                    self.helper.write_acknowledgement(target, acknowledgement)

            self.assertFalse(target.exists())
            self.assertTrue(attacker_link.is_file())
            self.assertEqual(
                self.helper.read_acknowledgement(attacker_link), acknowledgement
            )

    def test_bound_directory_blocks_or_detects_mid_write_namespace_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipts = root / "receipts"
            displaced = root / "displaced"
            receipts.mkdir()
            binding = self.helper._bind_directory(receipts, "receipts root")
            target = receipts / "receipt.json"
            acknowledgement = self.helper.make_acknowledgement(self._challenge_for(0))
            original_write = self.helper._write_all
            attempted = [False]

            def substitute_parent(descriptor: int, payload: bytes) -> None:
                attempted[0] = True
                if os.name == "nt":
                    with self.assertRaises(OSError):
                        receipts.rename(displaced)
                else:
                    receipts.rename(displaced)
                    receipts.mkdir()
                original_write(descriptor, payload)

            try:
                with mock.patch.object(self.helper, "_write_all", substitute_parent):
                    if os.name == "nt":
                        self.helper.write_acknowledgement(
                            target, acknowledgement, binding
                        )
                    else:
                        with self.assertRaisesRegex(
                            self.helper.AcknowledgementError,
                            "^acknowledgement parent identity changed$",
                        ):
                            self.helper.write_acknowledgement(
                                target, acknowledgement, binding
                            )
                self.assertTrue(attempted[0])
                if os.name == "nt":
                    self.assertEqual(
                        self.helper.read_acknowledgement(target), acknowledgement
                    )
                else:
                    self.assertEqual(tuple(displaced.iterdir()), ())
                    self.assertEqual(tuple(receipts.iterdir()), ())
            finally:
                self.helper._close_directory(binding)

    def test_mid_write_receipt_substitution_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            challenge = self._challenge_for(0)
            name = self.helper.CHALLENGE_NAMES[0]
            self.helper.write_challenge(challenges / name, challenge)
            target = receipts / name
            attacker = b"attacker-owned\n"
            original_write = self.helper._write_all

            def substitute_receipt(descriptor: int, payload: bytes) -> None:
                original_write(descriptor, payload)
                target.write_bytes(attacker)

            with mock.patch.object(self.helper, "_write_all", substitute_receipt):
                with self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^acknowledgement file already exists$",
                ):
                    self.helper.watch(
                        plan_root,
                        acknowledgement_root,
                        input_fn=lambda _prompt: "yes",
                    )
            self.assertEqual(target.read_bytes(), attacker)
            self.assertEqual(
                {path.name for path in receipts.iterdir()},
                {name},
            )

    @unittest.skipUnless(os.name == "nt", "Windows reparse contract")
    def test_windows_directory_binding_rejects_reparse_points(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            linked = root / "linked"
            target.mkdir()
            try:
                linked.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error.winerror}")
            with self.assertRaisesRegex(
                self.helper.AcknowledgementError,
                "^linked root is unsafe$",
            ):
                self.helper._bind_directory(linked, "linked root")
            metadata = type(
                "Metadata",
                (),
                {"st_file_attributes": 0x400, "st_reparse_tag": 0},
            )()
            self.assertTrue(self.helper._is_reparse(metadata))

    def test_interrupted_receipt_write_removes_only_its_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            challenge = self._challenge_for(0)
            name = self.helper.CHALLENGE_NAMES[0]
            self.helper.write_challenge(challenges / name, challenge)
            def interrupt_write(descriptor: int, payload: bytes) -> None:
                os.write(descriptor, payload[:1])
                raise KeyboardInterrupt

            with mock.patch.object(self.helper, "_write_all", interrupt_write):
                with self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^operator cancelled acknowledgement$",
                ):
                    self.helper.watch(
                        plan_root,
                        acknowledgement_root,
                        input_fn=lambda _prompt: "yes",
                    )
            self.assertFalse((receipts / name).exists())
            self.assertTrue((challenges / name).is_file())
            self.assertEqual(tuple(receipts.iterdir()), ())

    def test_watch_timeout_uses_injected_clock_and_bounded_polling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, _challenges, receipts = self._roots(
                directory
            )
            clock = [0.0]
            sleeps: list[float] = []

            def sleeper(seconds: float) -> None:
                sleeps.append(seconds)
                clock[0] += seconds

            with self.assertRaisesRegex(
                self.helper.AcknowledgementError,
                "^challenge wait timed out$",
            ):
                self.helper.watch(
                    plan_root,
                    acknowledgement_root,
                    input_fn=lambda _prompt: self.fail("prompted without a challenge"),
                    monotonic=lambda: clock[0],
                    sleeper=sleeper,
                    poll_interval=0.25,
                    deadline_seconds=1.0,
                )
            self.assertEqual(sleeps, [0.25, 0.25, 0.25, 0.25])
            self.assertEqual(tuple(receipts.iterdir()), ())

    def test_existing_replayed_linked_hardlinked_and_wrong_receipts_are_rejected(self) -> None:
        variants = ("existing", "replayed", "hardlinked", "wrong-identity", "symlink")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                plan_root, acknowledgement_root, challenges, receipts = self._roots(
                    directory
                )
                challenge = self._challenge_for(0)
                name = self.helper.CHALLENGE_NAMES[0]
                self.helper.write_challenge(challenges / name, challenge)
                target = receipts / name
                payload_challenge = challenge
                if variant == "wrong-identity":
                    payload_challenge = self._challenge_for(1)
                payload = self.helper.encode_acknowledgement(
                    self.helper.make_acknowledgement(payload_challenge)
                )
                if variant in ("existing", "replayed", "wrong-identity"):
                    target.write_bytes(payload)
                elif variant == "hardlinked":
                    victim = receipts / "victim.json"
                    victim.write_bytes(payload)
                    os.link(victim, target)
                else:
                    victim = receipts / "victim.json"
                    victim.write_bytes(payload)
                    try:
                        target.symlink_to(victim)
                    except (OSError, NotImplementedError):
                        continue
                with self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^acknowledgement file already exists$",
                ):
                    self.helper.watch(
                        plan_root,
                        acknowledgement_root,
                        input_fn=lambda _prompt: self.fail(
                            "prompted despite an existing receipt"
                        ),
                    )

    def test_linked_and_substituted_challenges_are_rejected_without_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            challenge = self._challenge_for(0)
            name = self.helper.CHALLENGE_NAMES[0]
            victim = challenges / "victim.json"
            victim.write_bytes(self.helper.encode_challenge(challenge))
            linked = challenges / name
            try:
                linked.symlink_to(victim)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^challenge file is unsafe$",
                ):
                    self.helper.watch(
                        plan_root,
                        acknowledgement_root,
                        input_fn=lambda _prompt: self.fail("prompted for linked challenge"),
                    )
                self.assertEqual(tuple(receipts.iterdir()), ())

        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, challenges, receipts = self._roots(
                directory
            )
            challenge = self._challenge_for(0)
            replacement = dict(challenge)
            replacement["nonce"] = "f" * 64
            name = self.helper.CHALLENGE_NAMES[0]
            challenge_path = challenges / name
            self.helper.write_challenge(challenge_path, challenge)
            answers = [0]

            def substitute(_prompt: str) -> str:
                answers[0] += 1
                if answers[0] == len(REQUIRED_CHECKS["7zip"]):
                    challenge_path.unlink()
                    self.helper.write_challenge(challenge_path, replacement)
                return "yes"

            with self.assertRaisesRegex(
                self.helper.AcknowledgementError,
                "^challenge file identity changed$",
            ):
                self.helper.watch(
                    plan_root,
                    acknowledgement_root,
                    input_fn=substitute,
                )
            self.assertEqual(tuple(receipts.iterdir()), ())

    def test_closed_cli_requires_two_unique_absolute_external_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, _challenges, _receipts = self._roots(
                directory
            )
            arguments = self.helper.parse_arguments(
                [
                    "--interaction-plan-root",
                    str(plan_root),
                    "--acknowledgement-root",
                    str(acknowledgement_root),
                ]
            )
            self.assertEqual(arguments.interaction_plan_root, plan_root)
            self.assertEqual(arguments.acknowledgement_root, acknowledgement_root)

        invalid = (
            [],
            ["--interaction-plan-root", "relative", "--acknowledgement-root", "also-relative"],
            [
                "--interaction-plan-root",
                str(ROOT),
                "--acknowledgement-root",
                str(ROOT.parent),
            ],
            [
                "--interaction-plan-root",
                str(ROOT.parent),
                "--interaction-plan-root",
                str(ROOT.parent),
                "--acknowledgement-root",
                str(ROOT.parent.parent),
            ],
        )
        for argv in invalid:
            with self.subTest(argv=argv), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                self.helper.parse_arguments(argv)

    def test_direct_watch_cannot_bypass_external_root_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_root, acknowledgement_root, _challenges, _receipts = self._roots(
                directory
            )
            cases = (
                (ROOT, acknowledgement_root),
                (plan_root, ROOT),
            )
            for candidate_plan, candidate_acknowledgements in cases:
                with self.subTest(
                    plan=candidate_plan,
                    acknowledgements=candidate_acknowledgements,
                ), self.assertRaisesRegex(
                    self.helper.AcknowledgementError,
                    "^watch root configuration is invalid$",
                ):
                    self.helper.watch(
                        candidate_plan,
                        candidate_acknowledgements,
                        input_fn=lambda _prompt: self.fail("unsafe watch prompted"),
                        monotonic=lambda: 1.0,
                        sleeper=lambda _seconds: self.fail("unsafe watch slept"),
                        deadline_seconds=1.0,
                    )


class AcknowledgementRepositoryValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        name = "validate_repository_for_acknowledgement_test"
        spec = importlib.util.spec_from_file_location(name, VALIDATOR)
        assert spec is not None and spec.loader is not None
        cls.validator = importlib.util.module_from_spec(spec)
        sys.modules[name] = cls.validator
        spec.loader.exec_module(cls.validator)

    def test_validator_binding_exists(self) -> None:
        self.assertTrue(
            hasattr(self.validator, "validate_macos_acknowledgement_surface"),
            "repository validator acknowledgement binding is missing",
        )

    def test_validator_reviews_both_files_with_bounded_nofollow_reads(self) -> None:
        self.assertEqual(
            self.validator.MACOS_ACKNOWLEDGEMENT_REVIEWED_PATHS,
            (
                "tests/test_macos_interaction_acknowledgements.py",
                "tools/confirm_macos_gui_interactions.py",
            ),
        )
        self.assertEqual(self.validator.validate_macos_acknowledgement_surface(), [])

        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory)
            for relative in self.validator.MACOS_ACKNOWLEDGEMENT_REVIEWED_PATHS:
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            original_root = self.validator.ROOT
            self.validator.ROOT = copied
            try:
                helper = copied / "tools" / "confirm_macos_gui_interactions.py"
                helper.write_bytes(
                    helper.read_bytes()
                    + b"#"
                    * (self.validator.MACOS_ACKNOWLEDGEMENT_MAX_SOURCE_BYTES + 1)
                )
                errors = self.validator.validate_macos_acknowledgement_surface()
                self.assertEqual(
                    errors,
                    ["macOS acknowledgement helper exceeds its source byte bound"],
                )
            finally:
                self.validator.ROOT = original_root

    @unittest.skipUnless(os.name == "nt", "Windows no-follow source-open contract")
    def test_validator_uses_native_open_reparse_point_for_reviewed_sources(self) -> None:
        native_open = self.validator._VALIDATOR_CREATE_FILE
        with mock.patch.object(
            self.validator,
            "_VALIDATOR_CREATE_FILE",
            wraps=native_open,
        ) as observed:
            source = self.validator._macos_acknowledgement_source(
                "tools/confirm_macos_gui_interactions.py",
                "helper",
            )

        self.assertIn("def watch(", source)
        observed.assert_called_once()
        arguments = observed.call_args.args
        self.assertEqual(arguments[1], 0x80000000 | 0x0080)
        self.assertEqual(arguments[2], 0x00000001)
        self.assertEqual(arguments[4], 3)
        self.assertEqual(arguments[5] & 0x00200000, 0x00200000)

    def test_validator_rejects_forbidden_side_effect_capabilities_without_reflection(self) -> None:
        forbidden = (
            "import socket",
            "import urllib.request",
            "import subprocess",
            "os.system('true')",
            "os.environ['PATH']",
            "shutil.which('python')",
            "ROOT / 'evidence.json'",
            "import os as filesystem\nfilesystem.system('true')",
            "__import__('socket')",
            "ROOT.joinpath('evidence.json').write_text('x')",
            "ctypes.CDLL('shell32')",
            "getattr(os, 'system')('true')",
            "Path('evidence.json').write_text('x')",
            "os.spawnl(0, 'tool')",
            "ctypes.pythonapi.PyRun_SimpleString(b'pass')",
            "from os import system as invoke\ninvoke('tool')",
            "from pathlib import Path\nPath('x').open('w')",
            "import ctypes\nctypes.WinDLL('kernel32').WinExec('tool', 0)",
            "import ctypes\nctypes.CDLL(None).system(b'tool')",
            "_KERNEL32.WinExec('tool', 0)",
            "getattr(__builtins__, 'open')('evidence.json', 'w')",
            "getattr(Path('evidence.json'), 'write_text')('x')",
            "vars(os)['system']('true')",
            (
                "_KERNEL32 = ctypes.WinDLL('kernel32')\n"
                "native_alias = _KERNEL32\n"
                "native_alias.WinExec('tool', 0)"
            ),
            (
                "_CREATE_FILE('evidence.json', 0x40000000, 0, None, "
                "2, 0, None)"
            ),
            "_MOVE_FILE('source.json', 'evidence.json', 0)",
            (
                "def invoke(native):\n"
                "    native.WinExec('tool', 0)\n"
                "invoke(_KERNEL32)"
            ),
            "native_holder = [_KERNEL32]\nnative_holder[0].WinExec('tool', 0)",
            "_MOVEFILE_WRITE_THROUGH = 0x1",
            "os.fsencode = lambda _value: b'/tmp/evidence.json'",
            "str = lambda _value: 'evidence.json'",
            "def shadow_builtin(str):\n    return str",
            "shadow_lambda = lambda bytes: bytes",
            "shadowed = [value for int in () for value in ()]",
            "match {}:\n    case {**str}:\n        pass",
        )
        for marker in forbidden:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                copied = Path(directory)
                for relative in self.validator.MACOS_ACKNOWLEDGEMENT_REVIEWED_PATHS:
                    target = copied / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, target)
                helper = copied / "tools" / "confirm_macos_gui_interactions.py"
                helper.write_text(
                    helper.read_text(encoding="utf-8") + "\n" + marker + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                original_root = self.validator.ROOT
                self.validator.ROOT = copied
                try:
                    self.assertEqual(
                        self.validator.validate_macos_acknowledgement_surface(),
                        [
                            "macOS acknowledgement helper uses a forbidden side-effect capability"
                        ],
                    )
                finally:
                    self.validator.ROOT = original_root

    def test_validator_allows_adjacent_read_only_ast_forms(self) -> None:
        allowed = (
            "readonly_flag = os.O_RDONLY",
            "readonly_name = Path('evidence.json').name",
            "local_marker = 1\nlocal_marker = 2",
        )
        for marker in allowed:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                copied = Path(directory)
                for relative in self.validator.MACOS_ACKNOWLEDGEMENT_REVIEWED_PATHS:
                    target = copied / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, target)
                helper = copied / "tools" / "confirm_macos_gui_interactions.py"
                helper.write_text(
                    helper.read_text(encoding="utf-8") + "\n" + marker + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                original_root = self.validator.ROOT
                self.validator.ROOT = copied
                try:
                    self.assertEqual(
                        self.validator.validate_macos_acknowledgement_surface(),
                        [],
                    )
                finally:
                    self.validator.ROOT = original_root


if __name__ == "__main__":
    unittest.main()
