"""Field masking rules engine.

A rules document looks like:

    {"rules": [
        {"field": "depth_m",   "action": "redact", "replacement": "***"},
        {"field": "lat",       "action": "round",  "precision": 2},
        {"field": "vessel_id", "action": "hash",   "length": 12},
        {"field": "note",      "action": "drop"}
    ]}

Fields are dot-separated paths into each submitted record.
"""
import copy
import hashlib
import re

from .canonical import canonical

ACTIONS = ("redact", "round", "hash", "drop")
MAX_RULES = 50

_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


def validate_rules(doc):
    """Return a list of validation errors (empty when the document is valid)."""
    errors = []
    if not isinstance(doc, dict):
        return ["rules document must be a JSON object"]
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        return ["'rules' must be a non-empty array"]
    if len(rules) > MAX_RULES:
        return ["at most %d rules are allowed" % MAX_RULES]
    seen = set()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append("rule[%d] must be an object" % i)
            continue
        field = rule.get("field")
        action = rule.get("action")
        if not isinstance(field, str) or not _FIELD_RE.match(field):
            errors.append("rule[%d].field must be a dot path of identifiers" % i)
        elif field in seen:
            errors.append("rule[%d].field %r is duplicated" % (i, field))
        else:
            seen.add(field)
        if action not in ACTIONS:
            errors.append("rule[%d].action must be one of %s" % (i, "/".join(ACTIONS)))
            continue
        if action == "round":
            precision = rule.get("precision", 2)
            if not isinstance(precision, int) or isinstance(precision, bool) or not 0 <= precision <= 6:
                errors.append("rule[%d].precision must be an integer in 0..6" % i)
        elif action == "hash":
            length = rule.get("length", 12)
            if not isinstance(length, int) or isinstance(length, bool) or not 4 <= length <= 64:
                errors.append("rule[%d].length must be an integer in 4..64" % i)
        elif action == "redact":
            if not isinstance(rule.get("replacement", "***"), str):
                errors.append("rule[%d].replacement must be a string" % i)
    return errors


def apply_rules(records, rules_doc):
    """Return masked copies of records; inputs are never mutated."""
    rules = rules_doc.get("rules", []) if isinstance(rules_doc, dict) else []
    out = []
    for record in records:
        masked = copy.deepcopy(record)
        for rule in rules:
            _apply_one(masked, rule)
        out.append(masked)
    return out


def _resolve_target(record, path):
    """Return (parent_dict, key) for a present dict-addressed target, else None."""
    node = record
    for segment in path[:-1]:
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    if not isinstance(node, dict):
        return None
    key = path[-1]
    if key not in node:
        return None
    return node, key


def _effective_rule(rule):
    """Rule as actually executed, with defaulted parameters materialized."""
    effective = dict(rule)
    if rule["action"] == "redact":
        effective.setdefault("replacement", "***")
    elif rule["action"] == "round":
        effective.setdefault("precision", 2)
    elif rule["action"] == "hash":
        effective.setdefault("length", 12)
    return effective


def _apply_one(record, rule):
    path = rule["field"].split(".")
    found = _resolve_target(record, path)
    if found is None:
        return
    node, key = found
    action = rule["action"]
    if action == "drop":
        del node[key]
    elif action == "redact":
        node[key] = rule.get("replacement", "***")
    elif action == "round":
        value = node[key]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            node[key] = round(float(value), rule.get("precision", 2))
    elif action == "hash":
        length = rule.get("length", 12)
        node[key] = hashlib.sha256(canonical(node[key]).encode("utf-8")).hexdigest()[:length]


def _apply_one_explained(record, rule):
    """Apply one rule and return an evidence descriptor, or None when the rule
    finds no target. Never embeds the pre-masking value."""
    path = rule["field"].split(".")
    found = _resolve_target(record, path)
    if found is None:
        return None
    node, key = found
    action = rule["action"]
    effective = _effective_rule(rule)
    if action == "drop":
        del node[key]
        return {
            "action": "drop",
            "present": False,
            "evidence": {
                "rule": effective,
                "removed": True,
                "note": "field removed from output; original value is not returned",
            },
        }
    if action == "redact":
        replacement = effective["replacement"]
        node[key] = replacement
        return {
            "action": "redact",
            "present": True,
            "output": replacement,
            "evidence": {
                "rule": effective,
                "replacement": replacement,
                "replacement_length": len(replacement),
                "note": "value replaced by the frozen rule's literal; original value is not returned",
            },
        }
    if action == "round":
        precision = effective["precision"]
        value = node[key]
        is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
        if is_number:
            rounded = round(float(value), precision)
            node[key] = rounded
            return {
                "action": "round",
                "present": True,
                "output": rounded,
                "evidence": {
                    "rule": effective,
                    "precision": precision,
                    "input_kind": "number",
                    "applied": True,
                },
            }
        return {
            "action": "round",
            "present": True,
            "output": value,
            "evidence": {
                "rule": effective,
                "precision": precision,
                "input_kind": type(value).__name__,
                "applied": False,
                "note": "target is not a JSON number; passed through unchanged",
            },
        }
    # hash
    length = effective["length"]
    digest = hashlib.sha256(canonical(node[key]).encode("utf-8")).hexdigest()[:length]
    node[key] = digest
    return {
        "action": "hash",
        "present": True,
        "output": digest,
        "evidence": {
            "rule": effective,
            "algorithm": "sha256",
            "canonical_input": True,
            "prefix_length": length,
            "note": "output is the length-prefixed sha256 of the canonical value; preimage is not returned",
        },
    }


def _iter_leaves(obj, prefix=()):
    """Yield (path_tuple, value) for every non-dict terminal (lists are terminals:
    rule paths only traverse objects)."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _iter_leaves(value, prefix + (key,))
    else:
        yield prefix, obj


def _dig(record, path):
    node = record
    for segment in path:
        if not isinstance(node, dict) or segment not in node:
            return None, False
        node = node[segment]
    return node, True


def explain_record(record, rules_doc):
    """Mask one record and produce per-field evidence.

    Returns ``(masked_record, fields)`` where ``fields`` is a path-sorted list
    of dicts::

        {"field": "depth_m", "action": "redact", "present": True,
         "output": "***", "evidence": {...}}

    Every output field is accounted for exactly once: fields hit by a rule are
    reported with that rule's descriptor; every other leaf is reported as
    ``keep``. Pre-masking values of dropped/replaced/hashed fields are
    deliberately absent from the evidence.
    """
    rules = rules_doc.get("rules", []) if isinstance(rules_doc, dict) else []
    masked = copy.deepcopy(record)
    staged = {}
    for rule in rules:
        descriptor = _apply_one_explained(masked, rule)
        if descriptor is not None:
            staged[rule["field"]] = descriptor

    # Later rules can overwrite or remove an earlier rule's target (overlapping
    # paths); a descriptor survives only when it still describes the output.
    hit = {}
    for field, descriptor in staged.items():
        path = tuple(field.split("."))
        value, exists = _dig(masked, path)
        if descriptor["present"]:
            if exists and value == descriptor["output"]:
                hit[field] = descriptor
        else:
            # Removed key: the surrounding object chain must still be intact,
            # otherwise a later ancestor rule collapsed the whole subtree.
            parent, parent_exists = _dig(masked, path[:-1])
            if parent_exists and isinstance(parent, dict):
                hit[field] = descriptor

    hit_paths = [tuple(field.split(".")) for field in hit]

    def covered_by_rule(path):
        for ancestor in hit_paths:
            if path == ancestor:
                return True
            if path[: len(ancestor)] == ancestor:
                value, exists = _dig(masked, ancestor)
                # The hitting rule collapsed the subtree (drop/redact/hash); a
                # pass-through (e.g. round on a non-number) leaves it intact.
                if not exists or not isinstance(value, dict):
                    return True
        return False

    fields = [dict({"field": field}, **descriptor) for field, descriptor in hit.items()]
    for path, _value in _iter_leaves(masked):
        if covered_by_rule(path):
            continue
        value, _exists = _dig(masked, path)
        fields.append({
            "field": ".".join(path),
            "action": "keep",
            "present": True,
            "output": value,
            "evidence": {
                "rule": None,
                "reason": "no masking rule transforms this field; value is retained as published",
            },
        })
    fields.sort(key=lambda entry: entry["field"])
    return masked, fields
