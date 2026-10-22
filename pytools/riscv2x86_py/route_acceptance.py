"""Explicit experiment acceptance checks; never issue a semantic verdict.

Central proof validation and provider audit remain mandatory. This checker
compares their published results to independently declared experiment goals.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

SCHEMA = "riscv2x86.route-acceptance-matrix.v1"
IDENTITIES = ("authorityIdentity", "effectRelationIdentity", "executionIdentity",
              "sourceObservationIdentity", "targetObservationIdentity", "evidenceIdentity")


def _relative(text):
    if not isinstance(text, str) or not text:
        raise ValueError("ACCEPTANCE_SOURCE_PATH_INVALID")
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("ACCEPTANCE_SOURCE_PATH_INVALID")
    return path


def validate_matrix(value):
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "cases"} or value["schemaVersion"] != SCHEMA:
        raise ValueError("ACCEPTANCE_SCHEMA_INVALID")
    if not isinstance(value["cases"], list) or not value["cases"]:
        raise ValueError("ACCEPTANCE_CASES_REQUIRED")
    from .l2_dimensions import L2Dimension, L2ClaimScope
    seen = set()
    for case in value["cases"]:
        fields = {"caseId", "sourceRelativePath", "sourceDigest", "levels", "dimensions", "notClaimedProperties"}
        if not isinstance(case, dict) or set(case) != fields:
            raise ValueError("ACCEPTANCE_CASE_FIELDS_INVALID")
        name = case["caseId"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", name) or name in seen:
            raise ValueError("ACCEPTANCE_CASE_ID_INVALID")
        seen.add(name)
        _relative(case["sourceRelativePath"])
        if not isinstance(case["sourceDigest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", case["sourceDigest"]):
            raise ValueError("ACCEPTANCE_SOURCE_DIGEST_INVALID")
        levels = case["levels"]
        if not isinstance(levels, list) or not {"L0", "L1", "L2"}.issubset(levels) or len(set(levels)) != len(levels) or set(levels) - {"L0", "L1", "L2", "L3"}:
            raise ValueError("ACCEPTANCE_LEVELS_INVALID")
        if not isinstance(case["dimensions"], dict) or not case["dimensions"]:
            raise ValueError("ACCEPTANCE_DIMENSIONS_REQUIRED")
        for name, policy in case["dimensions"].items():
            if not isinstance(name, str) or not name or not isinstance(policy, dict) or set(policy) != {"relationKinds", "claimScopes"}:
                raise ValueError("ACCEPTANCE_DIMENSION_POLICY_INVALID")
            if name not in {x.value for x in L2Dimension}:
                raise ValueError("ACCEPTANCE_DIMENSION_UNKNOWN")
            if set(policy["relationKinds"]) - {"exact", "strengthened", "runtime_mediated"} or set(policy["claimScopes"]) - {L2ClaimScope.ARCHITECTURAL.value, L2ClaimScope.APPROVED_FUNCTIONAL_RELATION.value}:
                raise ValueError("ACCEPTANCE_CLAIM_POLICY_UNSUPPORTED")
            for choices in policy.values():
                if not isinstance(choices, list) or not choices or any(not isinstance(x, str) or not x for x in choices) or len(set(choices)) != len(choices):
                    raise ValueError("ACCEPTANCE_DIMENSION_POLICY_INVALID")
        props = case["notClaimedProperties"]
        if not isinstance(props, list) or any(not isinstance(x, str) or not x for x in props) or len(set(props)) != len(props):
            raise ValueError("ACCEPTANCE_UNCLAIMED_PROPERTIES_INVALID")
    return value


def check(matrix, *, results, source_root):
    from .l2_results import L2FragmentResult, L2_FRAGMENT_RESULT_SCHEMAS
    validate_matrix(matrix)
    results = Path(results).resolve(); source_root = Path(source_root).resolve()
    records = []
    for goal in matrix["cases"]:
        failures = []; fragments = []
        try:
            source = (source_root / goal["sourceRelativePath"]).resolve()
            if not source.is_relative_to(source_root):
                raise ValueError("ACCEPTANCE_SOURCE_ESCAPE")
            if "sha256:" + sha256(source.read_bytes()).hexdigest() != goal["sourceDigest"]:
                raise ValueError("ACCEPTANCE_SOURCE_CHANGED")
            result = json.loads((results / "cases" / goal["caseId"] / "evaluation-result.json").read_text())
            if result.get("status") != "verified": failures.append("case-not-verified")
            sources = []
            for command in result.get("commands", []):
                args = command.get("command", [])
                if command.get("phase") == "translation" and "--source" in args:
                    sources.append(Path(args[args.index("--source") + 1]).resolve())
            if sources != [source]: failures.append("translation-source-binding-mismatch")
            selected = result.get("selectedAttemptIds", [])
            attempts = [a for a in result.get("attempts", []) if not selected or a.get("attemptArtifactId") in selected]
            if not attempts or len(set(selected)) != len(selected) or (selected and len(attempts) != len(selected)):
                failures.append("selected-attempts-incomplete")
            for attempt in attempts:
                if attempt.get("status") != "verified": failures.append("attempt-not-verified")
                layers = (attempt.get("validation") or {}).get("layers", [])
                for level in goal["levels"]:
                    matches = [x for x in layers if x.get("level") == level]
                    if len(matches) != 1 or matches[0].get("status") != "verified":
                        failures.append("layer-not-verified:" + level)
                for layer in layers:
                    if layer.get("level") != "L2": continue
                    detail = layer.get("detail")
                    if isinstance(detail, str): detail = json.loads(detail)
                    if not isinstance(detail, dict) or detail.get("schemaVersion") not in L2_FRAGMENT_RESULT_SCHEMAS:
                        raise ValueError("ACCEPTANCE_L2_FRAGMENT_RESULT_REQUIRED")
                    typed = L2FragmentResult.from_dict(detail)
                    if layer.get("evidenceIdentity") != typed.evidence_identity:
                        failures.append("layer-evidence-identity-mismatch")
                    fragment_id = detail.get("fragmentId")
                    if not fragment_id or fragment_id != attempt.get("fragmentId"):
                        failures.append("fragment-binding-mismatch")
                    fragments.append(fragment_id)
                    required = detail.get("requiredDimensions", [])
                    dimensions = detail.get("dimensionResults", {})
                    if detail.get("status") != "verified" or not required or len(set(required)) != len(required):
                        failures.append("fragment-not-verified")
                    # Extra obligations cannot disappear merely because the matrix omitted them.
                    for dimension in set(required) | set(goal["dimensions"]):
                        item = dimensions.get(dimension, {})
                        policy = goal["dimensions"].get(dimension)
                        if dimension not in required or item.get("status") != "verified" or item.get("dimension") != dimension:
                            failures.append("dimension-not-verified:" + dimension)
                        if any(not isinstance(item.get(k), str) or not item[k] for k in IDENTITIES):
                            failures.append("dimension-evidence-incomplete:" + dimension)
                        if set(item.get("notClaimedProperties", [])) - set(goal["notClaimedProperties"]):
                            failures.append("undeclared-claim-exclusion:" + dimension)
                        if policy is None:
                            failures.append("dimension-policy-missing:" + dimension)
                        elif item.get("relationKind") not in policy["relationKinds"] or item.get("claimScope") not in policy["claimScopes"]:
                            failures.append("dimension-claim-mismatch:" + dimension)
            if not fragments or len(set(fragments)) != len(fragments): failures.append("fragment-coverage-incomplete")
        except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
            failures.append(type(exc).__name__ + ":" + str(exc))
        records.append({"caseId": goal["caseId"], "goalSatisfied": not failures,
                        "failures": sorted(set(failures)), "fragments": fragments,
                        "notClaimedProperties": goal["notClaimedProperties"]})
    return {"schemaVersion": "riscv2x86.route-acceptance-result.v1",
            "goalSatisfied": all(x["goalSatisfied"] for x in records), "cases": records,
            "semanticApproval": False,
            "scope": "published evidence coverage and explicit claim policy; requires independent central proof validation and provider audit"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check(json.loads(args.matrix.read_text()), results=args.results, source_root=args.source_root)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["goalSatisfied"] else 1
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"failureStage": "acceptance-configuration", "detail": str(exc), "semanticApproval": False}))
        return 2


if __name__ == "__main__": raise SystemExit(main())
