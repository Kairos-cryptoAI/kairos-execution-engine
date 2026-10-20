"""Offline guards for the candidate-only claims CI integration wiring."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "tests" / "bootstrap_production_claims_ci.py").read_text(encoding="utf-8")


class ClaimsWorkflowRegressionTests(unittest.TestCase):
    def test_opt_in_is_scoped_to_bounded_existing_integration_job(self):
        job = WORKFLOW.split("  execution-journal-integration:\n", 1)[1]
        self.assertIn("timeout-minutes: 15", job)
        self.assertIn("image: timescale/timescaledb:2.28.3-pg16", job)
        self.assertIn("POSTGRES_PASSWORD: kairos_test", job)
        self.assertIn("uv sync --python 3.11 --locked --dev --extra evedex", job)
        self.assertIn("uv run --python 3.11 --locked --dev --extra evedex pytest -q -m integration", job)
        self.assertLess(
            job.index("python tests/bootstrap_production_claims_ci.py"),
            job.index("pytest -q -m integration"),
        )
        self.assertNotIn('KAIROS_PRODUCTION_CLAIMS_TEST_PROVISION: "1"', WORKFLOW)
        self.assertNotIn("KAIROS_PRODUCTION_CLAIMS_TEST_PROVISION: '1'", WORKFLOW)

    def test_bootstrap_requires_github_gate_and_uses_fixed_isolated_synthetic_identities(self):
        for exact_gate in (
            '"GITHUB_ACTIONS": "true"',
            '"GITHUB_REPOSITORY": "Kairos-cryptoAI/kairos-execution-engine"',
            '"GITHUB_JOB": "execution-journal-integration"',
            '"KAIROS_PRODUCTION_CLAIMS_CI_BOOTSTRAP": "1"',
        ):
            self.assertIn(exact_gate, BOOTSTRAP)
        self.assertIn('DATABASE = "kairos_production_evidence_ci_000000000001"', BOOTSTRAP)
        self.assertIn('OWNER_ROLE = "kairos_claim_owner_ci"', BOOTSTRAP)
        self.assertIn('RUNTIME_ROLE = "kairos_claim_runtime_ci"', BOOTSTRAP)
        self.assertIn("str(uuid4())", BOOTSTRAP)
        self.assertIn('"KAIROS_PRODUCTION_CLAIMS_TEST_PROVISION": "1"', BOOTSTRAP)
        self.assertRegex(BOOTSTRAP, re.compile(r"CREATE DATABASE .*OWNER", re.IGNORECASE))
        for privilege_guard in (
            "NOSUPERUSER",
            "NOCREATEDB",
            "NOCREATEROLE",
            "NOREPLICATION",
            "NOBYPASSRLS",
            "NOINHERIT",
        ):
            self.assertIn(privilege_guard, BOOTSTRAP)
        self.assertNotRegex(BOOTSTRAP, re.compile(r"\b(DROP|TRUNCATE)\b", re.IGNORECASE))
        self.assertNotIn("kairos_production_evidence_v1", BOOTSTRAP)
        self.assertNotIn("venue", BOOTSTRAP.lower())
        self.assertNotIn("api_key", BOOTSTRAP.lower())

    def test_environment_values_are_fresh_and_bound_to_test_only_database(self):
        from tests.bootstrap_production_claims_ci import DATABASE, github_environment_values

        first = github_environment_values("00000000-0000-4000-8000-000000000001")
        second = github_environment_values("00000000-0000-4000-8000-000000000002")
        self.assertEqual(first["KAIROS_PRODUCTION_CLAIMS_TEST_DATABASE"], DATABASE)
        self.assertNotEqual(
            first["KAIROS_PRODUCTION_CLAIMS_TEST_DATABASE_UUID"],
            second["KAIROS_PRODUCTION_CLAIMS_TEST_DATABASE_UUID"],
        )
        self.assertIn("claims-owner-ci-public-test-only", first["KAIROS_PRODUCTION_CLAIMS_TEST_OWNER_DSN"])
        self.assertIn(
            "claims-runtime-ci-public-test-only", first["KAIROS_PRODUCTION_CLAIMS_TEST_RUNTIME_DSN"]
        )

    def test_bootstrap_refuses_wrong_repository_job_and_missing_output_before_connect(self):
        from tests.bootstrap_production_claims_ci import validate_ci_environment

        self.assertLess(
            BOOTSTRAP.index("validate_ci_environment(os.environ)"), BOOTSTRAP.index("import asyncpg")
        )
        valid = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "Kairos-cryptoAI/kairos-execution-engine",
            "GITHUB_JOB": "execution-journal-integration",
            "KAIROS_PRODUCTION_CLAIMS_CI_BOOTSTRAP": "1",
            "GITHUB_ENV": "ephemeral-env-file",
        }
        self.assertEqual(validate_ci_environment(valid), "ephemeral-env-file")
        for name, value in (
            ("GITHUB_ACTIONS", "false"),
            ("GITHUB_REPOSITORY", "attacker/fork"),
            ("GITHUB_JOB", "quality"),
            ("KAIROS_PRODUCTION_CLAIMS_CI_BOOTSTRAP", "0"),
            ("GITHUB_ENV", ""),
        ):
            candidate = {**valid, name: value}
            with self.subTest(name=name), self.assertRaises(SystemExit):
                validate_ci_environment(candidate)


if __name__ == "__main__":
    unittest.main()
