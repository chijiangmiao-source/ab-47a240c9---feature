"""Per-record verifiable evidence for a *published* export.

The service only attests a record when all of the following hold:

1. the export is in the terminal ``PUBLISHED`` stage;
2. the on-disk artifact is present and its sha256 matches the frozen
   ``artifact_digest`` (the digest is still verifiable);
3. the requested stable index is in range;
4. re-deriving that record from the **frozen input** and the **frozen rules
   snapshot** reproduces the artifact's same-order record byte-for-byte
   (canonical equality).

Anything else is a typed refusal — the API never returns a guessed result.
The frozen snapshot (not the currently active rules) drives re-derivation, so
evidence for an old export always points at the rules version it shipped with.
"""
import hashlib
import json

from . import artifacts, masking, store
from .canonical import canonical, digest_of
from .render import GENERATOR, render_artifact_bytes


class EvidenceError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def rules_summary(rules_doc):
    """Human-checkable summary of a frozen rules document (no field values)."""
    rules = rules_doc.get("rules", []) if isinstance(rules_doc, dict) else []
    entries = []
    for rule in rules:
        entry = {"field": rule.get("field"), "action": rule.get("action")}
        if rule.get("action") == "round":
            entry["precision"] = rule.get("precision", 2)
        elif rule.get("action") == "hash":
            entry["length"] = rule.get("length", 12)
            entry["algorithm"] = "sha256"
        elif rule.get("action") == "redact":
            entry["replacement"] = rule.get("replacement", "***")
        entries.append(entry)
    body = canonical(rules_doc)
    return {
        "rules_version": None,  # filled in by build_evidence
        "rules_digest": digest_of(body),
        "rule_count": len(entries),
        "actions": entries,
    }


def _parse_artifact(data):
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(500, "artifact_unparseable",
                            "published artifact is not valid JSON: %s" % exc)
    if not isinstance(doc, dict) or not isinstance(doc.get("records"), list):
        raise EvidenceError(500, "artifact_malformed",
                            "published artifact does not carry a records array")
    return doc


def build_evidence(conn, export_id, index):
    """Verify, re-derive and compare one record. Returns the response payload.

    Raises EvidenceError on every condition that prevents attestation.
    """
    row = store.get_export(conn, export_id)
    if row is None:
        raise EvidenceError(404, "not_found", "unknown export_id: %s" % export_id)
    if row["stage"] != "PUBLISHED":
        raise EvidenceError(409, "not_published",
                            "export is in stage %s; evidence is available only after publication"
                            % row["stage"])
    try:
        data = artifacts.load_verified(row)
    except artifacts.ArtifactMissing:
        raise EvidenceError(410, "artifact_missing",
                            "published artifact file is gone; record cannot be verified")
    except artifacts.DigestMismatch:
        raise EvidenceError(410, "artifact_unverified",
                            "published artifact failed digest verification; evidence refused")

    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise EvidenceError(422, "invalid_index", "index must be a non-negative integer")

    doc = _parse_artifact(data)
    published_records = doc["records"]
    if index >= len(published_records):
        raise EvidenceError(404, "index_out_of_range",
                            "record index %d is out of range (artifact holds %d record(s))"
                            % (index, len(published_records)))

    # Re-derive strictly from the frozen decision — never from current rules.
    frozen_records = json.loads(row["records"])
    frozen_rules = json.loads(row["rules_snapshot"])
    if index >= len(frozen_records):
        raise EvidenceError(500, "replay_failed",
                            "frozen input holds fewer records than the artifact; refusing to guess")
    rederived_masked, fields = masking.explain_record(frozen_records[index], frozen_rules)

    published_record = published_records[index]
    if canonical(rederived_masked) != canonical(published_record):
        raise EvidenceError(410, "replay_mismatch",
                            "re-derived record %d does not match the published same-order record; "
                            "evidence refused" % index)

    # Whole-artifact re-derivation as an additional cross-check.
    expected_bytes = render_artifact_bytes(row)
    artifact_replay = hashlib.sha256(expected_bytes).hexdigest() == row["artifact_digest"]
    if not artifact_replay:
        raise EvidenceError(410, "replay_mismatch",
                            "frozen inputs do not reproduce the published artifact digest; "
                            "evidence refused")

    summary = rules_summary(frozen_rules)
    summary["rules_version"] = row["rules_version"]
    return {
        "status": "verified",
        "export_id": export_id,
        "record_index": index,
        "record_count": len(published_records),
        "receipt_id": row["receipt_id"],
        "received_at": row["received_at"],
        "published_at": row["published_at"],
        "frozen_rules": summary,
        "input_digest": row["input_digest"],
        "artifact_digest": row["artifact_digest"],
        "artifact_digest_verified": True,
        "replayed_from_frozen": True,
        "generator": doc.get("generator", GENERATOR),
        "masked_record": published_record,
        "fields": fields,
    }
