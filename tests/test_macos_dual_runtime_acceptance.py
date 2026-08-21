from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_TOOL = ROOT / "tools" / "run_macos_dual_runtime_acceptance.py"
VALIDATOR = ROOT / "scripts" / "validate_repository.py"

EXPECTED_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}
EXPECTED_REVIEWED_PATHS = (
    "tests/test_macos_dual_runtime_acceptance.py",
    "tools/run_macos_dual_runtime_acceptance.py",
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


acceptance = load_module("run_macos_dual_runtime_acceptance", ACCEPTANCE_TOOL)
validator = load_module("validate_repository_for_macos_acceptance", VALIDATOR)


class MacOsDualRuntimeAcceptanceContractTests(unittest.TestCase):
    def test_acceptance_matrix_is_exact_and_has_two_rounds(self) -> None:
        self.assertEqual(acceptance.RUNTIME_MATRIX, EXPECTED_MATRIX)
        self.assertEqual(acceptance.ROUNDS, ("round-1", "round-2"))

        expanded = tuple(
            (round_id, runtime_id, application_id)
            for round_id in acceptance.ROUNDS
            for runtime_id, application_ids in acceptance.RUNTIME_MATRIX.items()
            for application_id in application_ids
        )
        self.assertEqual(len(expanded), 16)
        self.assertEqual(len(set(expanded)), 16)

    def test_python_preflight_rejects_unsupported_interpreters(self) -> None:
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "^Python 3[.]11 or newer is required$"
        ):
            acceptance.require_python((3, 9, 11))

    def test_python_preflight_accepts_supported_interpreters(self) -> None:
        self.assertIsNone(acceptance.require_python((3, 11, 0)))
        self.assertIsNone(acceptance.require_python((3, 12, 13)))

    def test_repository_validator_binds_the_reviewed_acceptance_surface(self) -> None:
        self.assertEqual(
            validator.MACOS_ACCEPTANCE_REVIEWED_PATHS,
            EXPECTED_REVIEWED_PATHS,
        )
        self.assertEqual(validator.validate_macos_acceptance_surface(), [])

    def test_repository_validator_rejects_an_ancestor_link(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-macos-acceptance-validator-"
        ) as temporary:
            temporary_root = Path(temporary)
            repository_root = temporary_root / "repository"
            tests_root = repository_root / "tests"
            external_tools = temporary_root / "external-tools"
            tests_root.mkdir(parents=True)
            external_tools.mkdir()
            (tests_root / "test_macos_dual_runtime_acceptance.py").write_text(
                "# test fixture\n", encoding="utf-8"
            )
            (external_tools / "run_macos_dual_runtime_acceptance.py").write_text(
                "# external fixture\n", encoding="utf-8"
            )
            try:
                os.symlink(
                    external_tools,
                    repository_root / "tools",
                    target_is_directory=True,
                )
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with mock.patch.object(validator, "ROOT", repository_root):
                errors = validator.validate_macos_acceptance_surface()

            self.assertEqual(len(errors), 1)
            self.assertIn("tools/run_macos_dual_runtime_acceptance.py", errors[0])
            self.assertIn("unsafe path component", errors[0])


if __name__ == "__main__":
    unittest.main()
