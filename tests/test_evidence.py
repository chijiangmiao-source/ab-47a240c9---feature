import hashlib
import json
import os
import tempfile
import unittest

from app import artifacts, config, evidence, store, worker
from app.canonical import canonical


class EvidenceTestBase(unittest.TestCase):
    RULES = {"rules": [
        {"field": "depth_m", "action": "redact", "replacement": "***"},
        {"field": "lat", "action": "round", "precision": 2},
        {"field": "vessel_id", "action": "hash", "length": 12},
        {"field": "note", "action": "drop"},
    ]}
    RECORDS = [
        {"ts": "t0", "lat": 31.230416, "lon": 121.473701, "depth_m": 42.51,
         "vessel_id": "HAICE-01", "note": "secret-one"},
        {"ts": "t1", "lat": 31.231102, "lon": 121.480233, "depth_m": 43.04,
         "vessel_id": "HAICE-02", "note": "secret-two"},
    ]

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = self._tmp.name
        os.environ["LEASE_TTL_SECONDS"] = "5"
        config.ensure_dirs()
        self.conn = store.connect()
        store.init_db(self.conn)
        store.set_rules(self.conn, self.RULES)
        store.submit_export(self.conn, "E-1", self.RECORDS)

    def tearDown(self):
        self.conn.close()
        self._tmp.cleanup()
        for var in ("DATA_DIR", "LEASE_TTL_SECONDS"):
            os.environ.pop(var, None)

    def row(self):
        return store.get_export(self.conn, "E-1")

    def publish(self):
        fencing = store.acquire_lease(self.conn, worker.lease_resource("E-1"), "w-test", 5)
        self.assertEqual("published", worker.process_export(self.conn, "E-1", "w-test", fencing))
        return self.row()


class FieldEvidenceTest(EvidenceTestBase):
    def test_actions_and_masked_values_per_field(self):
        row = self.publish()
        ev = evidence.record_evidence(row, 0)
        self.assertEqual("E-1", ev["export_id"])
        self.assertEqual(0, ev["record_index"])
        self.assertEqual(2, ev["record_count"])
        self.assertEqual(row["rules_digest"], ev["rules_digest"])
        self.assertEqual(row["rules_version"], ev["rules_version"])
        self.assertEqual(self.RULES["rules"], ev["rules_summary"])
        self.assertEqual(row["artifact_digest"], ev["artifact_digest"])
        self.assertTrue(ev["replay"]["artifact_digest_verified"])
        self.assertTrue(ev["replay"]["whole_artifact_replay"])
        self.assertTrue(ev["replay"]["record_match"])
        fields = {f["field"]: f for f in ev["fields"]}
        self.assertEqual("keep", fields["ts"]["action"])
        self.assertEqual("t0", fields["ts"]["masked_value"])
        self.assertEqual("keep", fields["lon"]["action"])
        self.assertEqual(121.473701, fields["lon"]["masked_value"])
        self.assertEqual("round", fields["lat"]["action"])
        self.assertEqual(31.23, fields["lat"]["masked_value"])
        self.assertEqual("redact", fields["depth_m"]["action"])
        self.assertEqual("***", fields["depth_m"]["masked_value"])
        self.assertEqual("hash", fields["vessel_id"]["action"])
        self.assertEqual(12, len(fields["vessel_id"]["masked_value"]))
        self.assertEqual("drop", fields["note"]["action"])
        self.assertFalse(fields["note"]["present"])
        self.assertIsNone(fields["note"]["masked_value"])

    def test_evidence_never_contains_dropped_or_replaced_originals(self):
        row = self.publish()
        blob = json.dumps(evidence.record_evidence(row, 0), ensure_ascii=False)
        for original in ("42.51", "HAICE-01", "secret-one"):
            self.assertNotIn(original, blob)

    def test_record_matches_same_index_in_published_artifact(self):
        row = self.publish()
        ev = evidence.record_evidence(row, 1)
        artifact = json.loads(artifacts.load_verified(row).decode("utf-8"))
        self.assertEqual(canonical(artifact["records"][1]), canonical(ev["record"]))
        self.assertEqual("t1", ev["record"]["ts"])


class RejectionTest(EvidenceTestBase):
    def test_unpublished_export_is_refused(self):
        with self.assertRaises(evidence.NotPublished) as ctx:
            evidence.record_evidence(self.row(), 0)
        self.assertEqual(409, ctx.exception.status)
        self.assertEqual("not_published", ctx.exception.code)

    def test_out_of_range_index_is_refused(self):
        row = self.publish()
        for bad in (-1, 2, 99):
            with self.assertRaises(evidence.RecordNotFound) as ctx:
                evidence.record_evidence(row, bad)
            self.assertEqual(404, ctx.exception.status)

    def test_missing_artifact_is_refused(self):
        row = self.publish()
        os.unlink(row["artifact_path"])
        with self.assertRaises(artifacts.ArtifactMissing):
            evidence.record_evidence(self.row(), 0)

    def test_tampered_artifact_is_refused(self):
        row = self.publish()
        with open(row["artifact_path"], "ab") as fh:
            fh.write(b"tamper")
        with self.assertRaises(artifacts.DigestMismatch):
            evidence.record_evidence(self.row(), 0)

    def test_replay_mismatch_is_refused(self):
        """Attacker rewrites the artifact AND the bookkeeping digest: the
        re-derivation from the frozen decision still refuses to agree."""
        row = self.publish()
        doc = json.loads(artifacts.load_verified(row).decode("utf-8"))
        doc["records"][0]["ts"] = "forged"
        body = (canonical(doc) + "\n").encode("utf-8")
        with open(row["artifact_path"], "wb") as fh:
            fh.write(body)
        store.force_artifact_digest(self.conn, "E-1", hashlib.sha256(body).hexdigest())
        with self.assertRaises(evidence.ReplayMismatch) as ctx:
            evidence.record_evidence(self.row(), 0)
        self.assertEqual(409, ctx.exception.status)
        self.assertEqual("replay_mismatch", ctx.exception.code)

    def test_frozen_rules_snapshot_survives_later_rule_changes(self):
        row = self.publish()
        store.set_rules(self.conn, {"rules": [{"field": "lat", "action": "drop"}]})
        ev = evidence.record_evidence(self.row(), 0)
        self.assertEqual(row["rules_digest"], ev["rules_digest"])
        self.assertNotEqual(store.get_rules(self.conn)["digest"], ev["rules_digest"])
        fields = {f["field"]: f for f in ev["fields"]}
        self.assertEqual("round", fields["lat"]["action"])   # still the frozen rules
        self.assertEqual("redact", fields["depth_m"]["action"])


class NestedRuleTest(EvidenceTestBase):
    RULES = {"rules": [{"field": "pos.lat", "action": "round", "precision": 1}]}
    RECORDS = [{"ts": "t0", "pos": {"lat": 31.234, "lon": 121.47}, "depth_m": 10}]

    def test_nested_field_evidence(self):
        row = self.publish()
        ev = evidence.record_evidence(row, 0)
        fields = {f["field"]: f for f in ev["fields"]}
        self.assertEqual("round", fields["pos.lat"]["action"])
        self.assertEqual(31.2, fields["pos.lat"]["masked_value"])
        self.assertEqual("keep", fields["pos.lon"]["action"])
        self.assertEqual("keep", fields["depth_m"]["action"])


class AncestorRuleTest(EvidenceTestBase):
    RULES = {"rules": [{"field": "pos", "action": "drop"}]}
    RECORDS = [{"ts": "t0", "pos": {"lat": 31.2, "lon": 121.4}}]

    def test_ancestor_drop_marks_every_leaf_beneath(self):
        row = self.publish()
        ev = evidence.record_evidence(row, 0)
        fields = {f["field"]: f for f in ev["fields"]}
        self.assertEqual("drop", fields["pos.lat"]["action"])
        self.assertEqual("drop", fields["pos.lon"]["action"])
        self.assertFalse(fields["pos.lat"]["present"])
        self.assertIsNone(fields["pos.lat"]["masked_value"])
        self.assertEqual("keep", fields["ts"]["action"])


if __name__ == "__main__":
    unittest.main()
