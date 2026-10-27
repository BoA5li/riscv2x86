"""Read existing LR/SC artifacts; never run tools or change evidence.

Usage: python3 experiment/inspect_lrsc_basis.py --root RUN --output NEW.json
The root is the two-case diagnosis parent, not the whole results corpus.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path


NAMES = {"frontend-report.json", "raw_report.json", "translated_report.json",
         "compiler-candidates.json", "compiler-fragment-joins.json",
         "evaluation-result.json"}
FINDING_FIELDS = ("translationOutcome", "translationReasonCodes", "notes",
                  "machineCodeHex", "translationRuntimeFacts", "routeAuthorityDiagnostics",
                  "translationPlanAttempts", "verificationDetail", "l2SemanticProfile")


def collect(root):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("LRSC_BASIS_ROOT_MISSING")
    records, errors = [], []
    for path in sorted(p for p in root.rglob("*.json") if p.name in NAMES):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            errors.append({"path": str(path), "error": "external/symlink artifact rejected"})
            continue
        raw = path.read_bytes()
        record = {"path": str(path.relative_to(root)),
                  "sha256": sha256(raw).hexdigest(), "byteCount": len(raw)}
        try:
            data = json.loads(raw)
            findings = data if isinstance(data, list) else data.get("findings")
            if path.name in {"frontend-report.json", "raw_report.json", "translated_report.json"} and isinstance(findings, list):
                record["findings"] = []
                for finding in findings:
                    fragment = finding.get("fragment") or {}
                    authority = fragment.get("compilerFragmentAuthority") or {}
                    candidate = authority.get("candidate") or {}
                    outputs, inputs = fragment.get("outputs", []), fragment.get("inputs", [])
                    item = {k: finding.get(k) for k in FINDING_FIELDS}
                    item.update(fragmentId=fragment.get("fragmentId") or fragment.get("id"),
                                outputs=outputs, inputs=inputs,
                                outputCount=len(outputs), inputCount=len(inputs),
                                readWriteCount=sum(str(o.get("constraint", "")).startswith("+") for o in outputs),
                                compilerFragmentJoin=fragment.get("compilerFragmentJoin"),
                                compilerExpressionJoin=fragment.get("compilerExpressionJoin"),
                                compilerExpressionEvaluation=fragment.get("compilerExpressionEvaluation"),
                                compilerAuthorityIdentity=authority.get("authorityIdentity"),
                                compilerTypeBindings=authority.get("compilerTypeBindings"),
                                memoryObjectBindings=authority.get("memoryObjectBindings"),
                                candidate={k: candidate.get(k) for k in (
                                    "fragmentBindingKey", "operandBindings", "operandCarriers",
                                    "operandSlotFacts", "compilerExpressionFacts", "complete", "reasonCodes")},
                                approvalArtifact=finding.get("approvalArtifact"))
                    record["findings"].append(item)
            else:
                record["data"] = data
        except (ValueError, TypeError, AttributeError) as exc:
            errors.append({"path": str(path), "error": type(exc).__name__ + ": " + str(exc)})
        records.append(record)
    transitions = {}
    for record in records:
        for finding in record.get("findings", []):
            key = str(Path(record["path"]).parent) + ":" + str(finding["fragmentId"])
            transitions.setdefault(key, []).append({
                "report": record["path"], "outputCount": finding["outputCount"],
                "inputCount": finding["inputCount"], "readWriteCount": finding["readWriteCount"],
                "outputConstraints": [o.get("constraint") for o in finding["outputs"]],
                "inputConstraints": [o.get("constraint") for o in finding["inputs"]],
                "semanticProfileOperandShape": (finding.get("l2SemanticProfile") or {}).get("operandShape"),
            })
    sources = []
    for path in sorted((root / "inputs").glob("*.c")):
        if not path.is_symlink():
            raw = path.read_bytes()
            sources.append({"path": str(path.relative_to(root)),
                            "sha256": sha256(raw).hexdigest(), "text": raw.decode("utf-8")})
    return {"schemaVersion": "riscv2x86.lrsc-basis-snapshot.v1",
            "semanticApproval": False, "root": str(root), "sources": sources,
            "records": records, "boundaryTransitions": transitions, "errors": errors,
            "note": "Hashes identify diagnostic bytes; they grant no compiler/proof authority."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    data = collect(args.root)
    if not data["records"]:
        raise ValueError("LRSC_BASIS_ARTIFACTS_MISSING")
    with Path(args.output).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": args.output, "recordCount": len(data["records"]),
                      "sourceCount": len(data["sources"]), "errors": data["errors"]}))
    return 1 if data["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
