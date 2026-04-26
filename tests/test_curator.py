"""Unit tests for curator modules."""

import json
import pytest
from curator.validate import validate_schema, validate_semantics, _structural_score
from curator.preprocess import _strip_boilerplate, build_payload


def _minimal_pack(cve_id="CVE-2021-44228", ecosystem="npm",
                   package="lodash", confidence="low",
                   symbols=None, diff_available=False):
    """Build a minimal valid knowledge pack for testing."""
    return {
        "layer1": {
            "cve_id": cve_id,
            "ghsa_id": None,
            "aliases": [],
            "affected_ecosystem": ecosystem,
            "affected_package": package,
            "purl": f"pkg:npm/{package}",
            "summary": "A test vulnerability in the package.",
        },
        "layer2": {
            "vulnerable_versions": ["4.17.20"],
            "fixed_version": "4.17.21",
            "affected_ranges": [">=4.0.0 <4.17.21"],
            "fix_commit_sha": "abc123",
            "vuln_tag": "4.17.20",
            "fix_tag": "4.17.21",
        },
        "layer3": {
            "vulnerable_symbols": symbols or [],
            "vulnerable_symbol_callers": [],
            "fix_type": "code_change",
            "typical_fix_effort": {"level": "version_bump", "description": None, "diff_evidence": None},
        },
        "layer4": {
            "requires_user_input": False,
            "requires_authentication": False,
            "requires_network_access": True,
            "requires_specific_config": False,
            "requires_specific_features": False,
            "requires_specific_dependencies": False,
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "mitigations_available": False,
        },
        "layer5": {
            "not_affected_not_called": {
                "justification": "test", "impact_statement": "test", "action_statement": "test"
            },
            "not_affected_mitigated": {
                "justification": "test", "impact_statement": "test", "action_statement": "test"
            },
            "affected_default": {
                "justification": "test", "impact_statement": "test", "action_statement": "test"
            },
        },
        "layer6": {"import_patterns": [], "call_patterns": [], "config_patterns": []},
        "layer7": {
            "curated_by": "test",
            "curated_at": "2024-01-01T00:00:00+00:00",
            "prompt_version": "1.0.0",
            "model_version": "MiniMax-Text-01",
            "confidence_overall": confidence,
            "confidence_reasoning": "test",
            "human_reviewed": False,
            "review_notes": None,
            "source_diff_available": diff_available,
            "sources": ["osv.dev"],
            "last_validated_at": "2024-01-01T00:00:00+00:00",
            "schema_version": "1.0",
        },
    }


class TestValidateSchema:
    def test_valid_pack_passes(self):
        pack = _minimal_pack()
        errors = validate_schema(pack)
        assert errors == []

    def test_missing_cve_id_fails(self):
        pack = _minimal_pack()
        del pack["layer1"]["cve_id"]
        errors = validate_schema(pack)
        assert errors  # should have at least one error

    def test_invalid_cve_pattern_fails(self):
        pack = _minimal_pack(cve_id="NOT-A-CVE")
        errors = validate_schema(pack)
        assert errors


class TestValidateSemantics:
    def _prefill(self, cve_id="CVE-2021-44228", ecosystem="npm"):
        return {
            "cve_id": cve_id, "ecosystem": ecosystem,
            "attack_vector": "NETWORK", "attack_complexity": "LOW",
        }

    def test_rule1_no_diff_high_confidence_capped(self):
        pack = _minimal_pack(confidence="high", diff_available=False)
        pack, rules = validate_semantics(pack, self._prefill(), 0, False)
        assert pack["layer7"]["confidence_overall"] == "low"
        assert any("R1" in r for r in rules)

    def test_rule2_symbol_no_evidence_downgraded(self):
        symbols = [{"name": "exec", "kind": "function", "confidence": "high",
                     "reasoning": "test", "diff_evidence": None}]
        pack = _minimal_pack(confidence="medium", symbols=symbols, diff_available=True)
        pack, rules = validate_semantics(pack, self._prefill(), 0, False)
        assert pack["layer3"]["vulnerable_symbols"][0]["confidence"] == "low"

    def test_rule4_high_empty_symbols_raises(self):
        pack = _minimal_pack(confidence="high", symbols=[], diff_available=True)
        # Add diff_available to make rule4 trigger
        pack["layer7"]["source_diff_available"] = True
        with pytest.raises(ValueError, match="R4"):
            validate_semantics(pack, self._prefill(), 0, False)

    def test_rule7_field_mismatch_raises(self):
        pack = _minimal_pack(cve_id="CVE-2021-44228")
        prefill = self._prefill(cve_id="CVE-2022-9999")
        with pytest.raises(ValueError, match="R7"):
            validate_semantics(pack, prefill, 0, False)

    def test_rule5_correction_caps_high_to_medium(self):
        # Need symbols with evidence so structural ceiling is >= medium
        symbols = [{"name": "exec", "kind": "function", "confidence": "high",
                     "reasoning": "test", "diff_evidence": "- exec(cmd)\n+ sanitize(cmd)"}]
        pack = _minimal_pack(confidence="high", symbols=symbols, diff_available=True)
        pack, rules = validate_semantics(pack, self._prefill(), 0, correction_used=True)
        # Rule 5: correction_used caps high → medium
        assert pack["layer7"]["confidence_overall"] == "medium"
        assert any("R5" in r for r in rules)


class TestPreprocess:
    def test_strip_boilerplate_removes_copyright(self):
        text = "// Copyright 2020 Foo Corp\nfunction exec() {}"
        result = _strip_boilerplate(text)
        assert "Copyright" not in result
        assert "exec" in result

    def test_build_payload_prefill_deterministic(self):
        ctx = {
            "advisory": None,
            "diff_available": False,
            "diff_text": None,
            "fix_commit_sha": None,
            "vuln_tag": None,
            "fix_tag": None,
        }
        payload = build_payload(ctx, "CVE-2021-44228", "npm", "lodash", "4.17.20", "4.17.21")
        assert payload["prefill"]["cve_id"] == "CVE-2021-44228"
        assert payload["prefill"]["ecosystem"] == "npm"
        assert payload["prefill"]["package"] == "lodash"
        assert payload["diff_available"] is False
