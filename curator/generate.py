"""5-step LLM prompt chain using MiniMax M2.5 (OpenAI-compatible)."""

import json
import logging
import os
from typing import Any
from datetime import datetime, timezone
from openai import OpenAI

logger = logging.getLogger(__name__)

PROMPT_VERSION = "1.0.0"
MODEL = "MiniMax-Text-01"
MAX_RETRIES = 2


def _client() -> OpenAI:
    return OpenAI(
        api_key=os.environ["MINIMAX_API_KEY"],
        base_url="https://api.minimax.io/v1",
    )


def _system_prompt() -> str:
    base = os.environ.get("MINIMAX_SYSTEM_PROMPT", "")
    if base:
        return base
    return (
        "You are a security vulnerability analyst. You produce structured JSON knowledge packs "
        "about CVEs. You MUST follow these rules:\n"
        "1. ONLY use evidence from the provided diff and advisory. Never use training knowledge as evidence.\n"
        "2. Every vulnerable symbol claim MUST include verbatim diff_evidence from the provided diff.\n"
        "3. If no diff is available, set confidence to 'low' for all symbol claims.\n"
        "4. Deterministic fields (cve_id, ecosystem, package, versions, attack_vector, "
        "attack_complexity) are pre-filled and must not be modified.\n"
        "Respond ONLY with valid JSON matching the requested schema."
    )


def _chat(client: OpenAI, messages: list[dict], retry_count: int = 0) -> str:
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=messages,
                temperature=0.1,
                # response_format not used — MiniMax doesn't support json_object mode.
                # JSON output is enforced via the system prompt instruction.
            )
            return _extract_json_text(resp.choices[0].message.content or "{}")
        except Exception as e:
            logger.warning("LLM call attempt %d failed: %s", attempt + 1, e)
            if attempt >= MAX_RETRIES:
                raise
    return "{}"


def _extract_json_text(text: str) -> str:
    """Strip markdown code fences the model may wrap around JSON."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop first line (```json or ```) and last line (```)
        inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
        text = "\n".join(inner).strip()
    return text


def _parse_json(text: str, fallback: dict | None = None) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.error("LLM returned invalid JSON: %s — %s", e, text[:200])
        if fallback is not None:
            return fallback
        raise RuntimeError(f"LLM invalid JSON: {e}") from e


def run_chain(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """
    Execute the 5-step prompt chain.
    Returns (raw_llm_output, retry_count).
    """
    client = _client()
    prefill = payload["prefill"]
    adv = payload["advisory_text"]
    diff = payload["diff_text"]
    diff_available = payload["diff_available"]

    context_block = f"""
CVE ID: {prefill['cve_id']}
Ecosystem: {prefill['ecosystem']}
Package: {prefill['package']}
Vulnerable version: {prefill['vuln_version']}
Fixed version: {prefill['fix_version']}
Attack vector: {prefill['attack_vector']}
Attack complexity: {prefill['attack_complexity']}
Fix commit SHA: {prefill['fix_commit_sha'] or 'unavailable'}
Diff available: {diff_available}

=== ADVISORY ===
{adv}

=== DIFF ===
{diff if diff_available else 'No diff available for this CVE.'}
"""

    retry_count = 0
    correction_used = False

    # Step 1: Advisory parsing — extract versions, GHSA, aliases
    step1_prompt = (
        f"{context_block}\n\nStep 1 — Advisory Parser:\n"
        "Return JSON with fields: ghsa_id, aliases (array), summary, "
        "vulnerable_versions (array of version strings), fixed_version (string or null), "
        "affected_ranges (array of range strings).\n"
        "Use ONLY the advisory text above."
    )
    step1_raw = _chat(client, [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": step1_prompt},
    ])
    step1 = _parse_json(step1_raw, {})

    # Step 2: Diff analysis — which files/functions changed
    if diff_available and diff:
        step2_prompt = (
            f"{context_block}\n\nStep 2 — Diff Analyzer:\n"
            "Analyze the diff above. Return JSON with: changed_files (array of filenames), "
            "key_changes (array of short descriptions of what changed and why it matters for security)."
        )
        step2_raw = _chat(client, [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": step2_prompt},
        ])
        step2 = _parse_json(step2_raw, {"changed_files": [], "key_changes": []})
    else:
        step2 = {"changed_files": [], "key_changes": []}

    # Step 3: Symbol extraction — vulnerable functions/methods
    step3_prompt = (
        f"{context_block}\n\nAnalysis so far:\n{json.dumps(step2, indent=2)}\n\n"
        "Step 3 — Symbol Extractor:\n"
        "Return JSON with: vulnerable_symbols (array). Each symbol must have: "
        "name, kind (function/method/class/variable/module), class (or null), "
        "signature (or null), file_path (or null), confidence (high/medium/low), "
        "reasoning (one sentence), diff_evidence (verbatim excerpt from diff, or null).\n"
        "RULE: If no diff is available, ALL symbols must have confidence='low' and diff_evidence=null.\n"
        "RULE: You MUST provide diff_evidence for any high or medium confidence symbol."
    )
    step3_raw = _chat(client, [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": step3_prompt},
    ])
    step3 = _parse_json(step3_raw, {"vulnerable_symbols": []})

    # Correction pass: if LLM violated evidence rule, fix it
    symbols = step3.get("vulnerable_symbols", [])
    violations = [
        s for s in symbols
        if s.get("confidence") in ("high", "medium") and not s.get("diff_evidence")
    ]
    if violations and diff_available:
        correction_used = True
        retry_count += 1
        logger.info("Symbol evidence violations found (%d), running correction pass", len(violations))
        fix_prompt = (
            f"The following symbols lack required diff_evidence:\n"
            f"{json.dumps(violations, indent=2)}\n\n"
            f"Here is the diff:\n{diff[:8000]}\n\n"
            "For each symbol, either find verbatim diff evidence and add it, "
            "or downgrade confidence to 'low'. "
            "Return the COMPLETE corrected vulnerable_symbols array as JSON: "
            '{"vulnerable_symbols": [...]}'
        )
        fix_raw = _chat(client, [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": fix_prompt},
        ])
        fixed = _parse_json(fix_raw, step3)
        step3["vulnerable_symbols"] = fixed.get("vulnerable_symbols", symbols)

    # Step 4: Exploitability classification
    step4_prompt = (
        f"{context_block}\n\nSymbols: {json.dumps(step3.get('vulnerable_symbols', [])[:5], indent=2)}\n\n"
        "Step 4 — Exploitability Classifier:\n"
        "Return JSON with boolean fields: requires_user_input, requires_authentication, "
        "requires_network_access, requires_specific_config, requires_specific_features, "
        "requires_specific_dependencies, mitigations_available.\n"
        "Base your answers ONLY on the advisory and diff above."
    )
    step4_raw = _chat(client, [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": step4_prompt},
    ])
    step4 = _parse_json(step4_raw, {
        "requires_user_input": False, "requires_authentication": False,
        "requires_network_access": True, "requires_specific_config": False,
        "requires_specific_features": False, "requires_specific_dependencies": False,
        "mitigations_available": False,
    })

    # Step 5: Knowledge pack assembly
    step5_prompt = (
        f"{context_block}\n\n"
        f"Advisory parsed: {json.dumps(step1, indent=2)}\n"
        f"Symbols: {json.dumps(step3, indent=2)}\n"
        f"Exploitability: {json.dumps(step4, indent=2)}\n\n"
        "Step 5 — Knowledge Pack Assembler:\n"
        "Return JSON with:\n"
        "- vex_templates: object with not_affected_not_called, not_affected_mitigated, affected_default. "
        "Each has justification, impact_statement, action_statement.\n"
        "- detection_patterns: object with import_patterns (array), call_patterns (array), config_patterns (array).\n"
        "- vulnerable_symbol_callers: array of function/class names that call the vulnerable symbols.\n"
        "- fix_type: one of version_bump/config_change/code_change/complex_refactor (or null).\n"
        "- typical_fix_effort: object with level (version_bump/config_change/code_change/complex_refactor/unknown), "
        "description (string or null), diff_evidence (verbatim from diff or null).\n"
        "- confidence_overall: high/medium/low.\n"
        "- confidence_reasoning: one sentence.\n"
        "Use ONLY evidence from the provided context. Do NOT invent data."
    )
    step5_raw = _chat(client, [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": step5_prompt},
    ])
    step5 = _parse_json(step5_raw, {})

    raw_output = {
        "step1": step1,
        "step2": step2,
        "step3": step3,
        "step4": step4,
        "step5": step5,
        "correction_used": correction_used,
        "retry_count": retry_count,
    }
    return raw_output, retry_count


def assemble_pack(payload: dict[str, Any], llm_output: dict[str, Any],
                  retry_count: int) -> dict[str, Any]:
    """Assemble the full knowledge pack from prefill + LLM output."""
    prefill = payload["prefill"]
    s1 = llm_output.get("step1", {})
    s3 = llm_output.get("step3", {})
    s4 = llm_output.get("step4", {})
    s5 = llm_output.get("step5", {})
    correction_used = llm_output.get("correction_used", False)

    now = datetime.now(timezone.utc).isoformat()

    pack: dict[str, Any] = {
        "layer1": {
            "cve_id": prefill["cve_id"],
            "ghsa_id": s1.get("ghsa_id"),
            "aliases": s1.get("aliases", []),
            "affected_ecosystem": prefill["ecosystem"],
            "affected_package": prefill["package"],
            "purl": _build_purl(prefill["ecosystem"], prefill["package"]),
            "summary": s1.get("summary", ""),
        },
        "layer2": {
            "vulnerable_versions": s1.get("vulnerable_versions", []),
            "fixed_version": prefill["fix_version"] or s1.get("fixed_version"),
            "affected_ranges": s1.get("affected_ranges", []),
            "fix_commit_sha": prefill["fix_commit_sha"],
            "vuln_tag": prefill["vuln_tag"],
            "fix_tag": prefill["fix_tag"],
        },
        "layer3": {
            "vulnerable_symbols": s3.get("vulnerable_symbols", []),
            "vulnerable_symbol_callers": s5.get("vulnerable_symbol_callers", []),
            "fix_type": s5.get("fix_type"),
            "typical_fix_effort": s5.get("typical_fix_effort"),
        },
        "layer4": {
            "requires_user_input":            s4.get("requires_user_input", False),
            "requires_authentication":        s4.get("requires_authentication", False),
            "requires_network_access":        s4.get("requires_network_access", True),
            "requires_specific_config":       s4.get("requires_specific_config", False),
            "requires_specific_features":     s4.get("requires_specific_features", False),
            "requires_specific_dependencies": s4.get("requires_specific_dependencies", False),
            "attack_vector":     prefill["attack_vector"],
            "attack_complexity": prefill["attack_complexity"],
            "mitigations_available": s4.get("mitigations_available", False),
        },
        "layer5": s5.get("vex_templates", {
            "not_affected_not_called": {
                "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": "The vulnerable function is not called in this configuration.",
                "action_statement": "No action required if the vulnerable symbol is not invoked.",
            },
            "not_affected_mitigated": {
                "justification": "inline_mitigations_already_exist",
                "impact_statement": "Existing mitigations prevent exploitation.",
                "action_statement": "Verify mitigations remain in place on each dependency update.",
            },
            "affected_default": {
                "justification": "component_not_present",
                "impact_statement": "The affected component is present and may be reachable.",
                "action_statement": f"Upgrade {prefill['package']} to {prefill['fix_version'] or 'the fixed version'}.",
            },
        }),
        "layer6": {
            "import_patterns": s5.get("detection_patterns", {}).get("import_patterns", []),
            "call_patterns":   s5.get("detection_patterns", {}).get("call_patterns", []),
            "config_patterns": s5.get("detection_patterns", {}).get("config_patterns", []),
        },
        "layer7": {
            "curated_by":      "vulnrank-pipeline",
            "curated_at":      now,
            "prompt_version":  PROMPT_VERSION,
            "model_version":   MODEL,
            "confidence_overall":  s5.get("confidence_overall", "low"),
            "confidence_reasoning": s5.get("confidence_reasoning"),
            "human_reviewed":  False,
            "review_notes":    None,
            "source_diff_available": prefill["diff_available"],
            "sources":         ["osv.dev", "github.com"] if prefill["diff_available"] else ["osv.dev"],
            "last_validated_at": now,
            "schema_version":  "1.0",
        },
    }

    # Post-LLM field surgery (Rule 4): restore all pre-filled deterministic fields
    pack["layer1"]["cve_id"] = prefill["cve_id"]
    pack["layer1"]["affected_ecosystem"] = prefill["ecosystem"]
    pack["layer1"]["affected_package"] = prefill["package"]
    pack["layer2"]["fix_commit_sha"] = prefill["fix_commit_sha"]
    pack["layer4"]["attack_vector"] = prefill["attack_vector"]
    pack["layer4"]["attack_complexity"] = prefill["attack_complexity"]

    return pack


def _build_purl(ecosystem: str, package: str) -> str:
    type_map = {
        "npm": "npm", "pypi": "pypi", "go": "golang",
        "maven": "maven", "cargo": "cargo", "nuget": "nuget", "rubygems": "gem",
    }
    purl_type = type_map.get(ecosystem, ecosystem)
    if ecosystem == "maven" and ":" in package:
        group, artifact = package.split(":", 1)
        return f"pkg:maven/{group}/{artifact}"
    return f"pkg:{purl_type}/{package}"
