"""Per-record evidence for published exports.

The duty officer picks one record of a published export; the service re-derives
that record from the frozen input and rules snapshot, compares it against the
same-index record of the digest-verified published artifact, and reports the
stable index, the frozen rules summary, the masked field values, and per-field
evidence of the applied action (keep / drop / redact / round / hash).

Evidence values always come from the masked (already published) record, so
originals that were dropped or replaced are never exposed. Anything that cannot
be proven — unpublished export, out-of-range index, missing/tampered artifact,
replay disagreement — is refused with an explicit error, never a guessed result.
"""
import hashlib
import json

from . import artifacts
from .canonical import canonical
from .masking import apply_rules
from .render import render_artifact_bytes


class EvidenceError(Exception):
    """Refusal with an HTTP-mappable status/code; never a guessed result."""

    status = 500
    code = "evidence_error"

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class NotPublished(EvidenceError):
    status = 409
    code = "not_published"


class RecordNotFound(EvidenceError):
    status = 404
    code = "record_not_found"


class ReplayMismatch(EvidenceError):
    status = 409
    code = "replay_mismatch"


def _leaf_paths(obj, prefix=""):
    """Dotted paths of every leaf (scalars, arrays, empty objects)."""
    if isinstance(obj, dict) and obj:
        paths = []
        for key in sorted(obj):
            child = "%s.%s" % (prefix, key) if prefix else key
            paths.extend(_leaf_paths(obj[key], child))
        return paths
    return [prefix]


def _lookup(obj, path):
    node = obj
    for segment in path.split("."):
        if not isinstance(node, dict) or segment not in node:
            return False, None
        node = node[segment]
    return True, node


def _rule_for(rules, path):
    """Exact rule for the path, else the nearest ancestor rule (a rule on a
    parent object, e.g. dropping a whole subtree, marks every leaf below it)."""
    best = None
    for rule in rules:
        field = rule.get("field", "")
        if field == path:
            return rule
        if path.startswith(field + ".") and (best is None or len(field) > len(best["field"])):
            best = rule
    return best


def build_field_evidence(original, masked, rules_doc):
    """One entry per leaf of the original record. Values are always taken from
    the masked record; a dropped or replaced original never appears."""
    rules = rules_doc.get("rules", []) if isinstance(rules_doc, dict) else []
    fields = []
    for path in _leaf_paths(original):
        rule = _rule_for(rules, path)
        present, value = _lookup(masked, path)
        entry = {
            "field": path,
            "action": rule["action"] if rule else "keep",
            "present": present,
            "masked_value": value if present else None,
        }
        if rule:
            entry["rule"] = rule
        fields.append(entry)
    return fields


def record_evidence(export_row, record_index):
    """Evidence that record `record_index` was produced by the frozen decision.

    Raises EvidenceError / artifacts.ArtifactMissing / artifacts.DigestMismatch
    instead of ever returning a guessed result.
    """
    if export_row["stage"] != "PUBLISHED":
        raise NotPublished(
            "export is in stage %s; evidence requires a published, verifiable artifact"
            % export_row["stage"]
        )
    # The published bytes must still match the digest frozen at publish time.
    data = artifacts.load_verified(export_row)
    try:
        artifact = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplayMismatch("published artifact is not valid JSON: %s" % exc)

    records_frozen = json.loads(export_row["records"])
    if not 0 <= record_index < len(records_frozen):
        raise RecordNotFound(
            "record index %d out of range; the frozen input holds %d record(s)"
            % (record_index, len(records_frozen))
        )
    rules_doc = json.loads(export_row["rules_snapshot"])

    # Whole-artifact replay: the frozen input + rules snapshot must reproduce
    # the very digest that was published.
    replayed = render_artifact_bytes(export_row)
    if hashlib.sha256(replayed).hexdigest() != export_row["artifact_digest"]:
        raise ReplayMismatch(
            "re-derivation from the frozen input and rules does not reproduce the "
            "published artifact digest; refusing to guess"
        )

    artifact_records = artifact.get("records") if isinstance(artifact, dict) else None
    if not isinstance(artifact_records, list) or len(artifact_records) != len(records_frozen):
        raise ReplayMismatch("published artifact records do not align with the frozen input")

    # Per-record replay: re-derive this record and compare it with the
    # same-index record of the published artifact.
    rederived = apply_rules([records_frozen[record_index]], rules_doc)[0]
    if canonical(rederived) != canonical(artifact_records[record_index]):
        raise ReplayMismatch(
            "record %d re-derived from the frozen decision does not match the "
            "published artifact" % record_index
        )

    return {
        "export_id": export_row["export_id"],
        "record_index": record_index,
        "record_count": len(records_frozen),
        "input_digest": export_row["input_digest"],
        "rules_digest": export_row["rules_digest"],
        "rules_version": export_row["rules_version"],
        "rules_summary": rules_doc.get("rules", []),
        "artifact_digest": export_row["artifact_digest"],
        "published_at": export_row["published_at"],
        "replay": {
            "artifact_digest_verified": True,
            "whole_artifact_replay": True,
            "record_match": True,
        },
        "record": rederived,
        "fields": build_field_evidence(records_frozen[record_index], rederived, rules_doc),
    }
