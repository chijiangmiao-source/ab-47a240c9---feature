import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from app import artifacts, config, evidence, masking, server, store, worker


RECORDS = [
    {"ts": "2026-10-06T01:00:00Z", "lat": 31.230416, "lon": 121.473701,
     "depth_m": 42.51, "vessel_id": "HAICE-01", "note": "TOP-SECRET-TEXT"},
    {"ts": "2026-10-06T01:05:00Z", "lat": 31.231102, "lon": 121.480233,
     "depth_m": 43.04, "vessel_id": "HAICE-01", "note": "TOP-SECRET-TEXT"},
]

RULES = {"rules": [
    {"field": "depth_m", "action": "redact"},
    {"field": "lat", "action": "round", "precision": 2},
    {"field": "vessel_id", "action": "hash", "length": 10},
    {"field": "note", "action": "drop"},
]}


class EvidenceTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = self._tmp.name
        os.environ["LEASE_TTL_SECONDS"] = "30"
        config.ensure_dirs()
        self.conn = store.connect()
        store.init_db(self.conn)

    def tearDown(self):
        self.conn.close()
        self._tmp.cleanup()
        for var in ("DATA_DIR", "LEASE_TTL_SECONDS"):
            os.environ.pop(var, None)

    def publish(self, export_id, records, rules_doc=None):
        if rules_doc is not None:
            store.set_rules(self.conn, rules_doc)
        store.submit_export(self.conn, export_id, records)
        fencing = store.acquire_lease(self.conn, worker.lease_resource(export_id), "w-test", 30)
        self.assertEqual("published", worker.process_export(self.conn, export_id, "w-test", fencing))
        return store.get_export(self.conn, export_id)

    def expect_refusal(self, export_id, index, code):
        with self.assertRaises(evidence.EvidenceError) as ctx:
            evidence.build_evidence(self.conn, export_id, index)
        self.assertEqual(code, ctx.exception.code)
        return ctx.exception


class ExplainRecordTest(unittest.TestCase):
    def test_each_action_reported_with_masked_output(self):
        masked, fields = masking.explain_record(RECORDS[0], RULES)
        by_field = {f["field"]: f for f in fields}
        self.assertEqual("***", masked["depth_m"])
        self.assertEqual(31.23, masked["lat"])
        self.assertNotIn("note", masked)
        self.assertEqual(10, len(masked["vessel_id"]))
        self.assertEqual("redact", by_field["depth_m"]["action"])
        self.assertEqual("***", by_field["depth_m"]["output"])
        self.assertEqual("round", by_field["lat"]["action"])
        self.assertEqual(31.23, by_field["lat"]["output"])
        self.assertTrue(by_field["lat"]["evidence"]["applied"])
        self.assertEqual("hash", by_field["vessel_id"]["action"])
        self.assertEqual("drop", by_field["note"]["action"])
        self.assertFalse(by_field["note"]["present"])
        self.assertEqual("keep", by_field["ts"]["action"])
        self.assertEqual(RECORDS[0]["ts"], by_field["ts"]["output"])
        self.assertEqual("keep", by_field["lon"]["action"])

    def test_dropped_subtree_claims_nested_leaves(self):
        rules = {"rules": [{"field": "meta", "action": "drop"}]}
        record = {"a": 1, "meta": {"secret": "X", "nested": {"y": 2}}}
        masked, fields = masking.explain_record(record, rules)
        self.assertEqual({"a": 1}, masked)
        names = [f["field"] for f in fields]
        self.assertIn("meta", names)
        self.assertNotIn("meta.secret", names)
        self.assertNotIn("meta.nested.y", names)
        self.assertIn("a", names)

    def test_overlapping_rules_report_only_rules_visible_in_output(self):
        # Ancestor drop after a child hash: the subtree is gone, so only the
        # ancestor rule may appear; a stale child descriptor must not survive.
        rules = {"rules": [
            {"field": "meta.secret", "action": "hash", "length": 8},
            {"field": "meta", "action": "drop"},
        ]}
        record = {"a": 1, "meta": {"secret": "X", "b": 2}}
        masked, fields = masking.explain_record(record, rules)
        self.assertEqual({"a": 1}, masked)
        actions = {f["field"]: f["action"] for f in fields}
        self.assertEqual({"a": "keep", "meta": "drop"}, actions)

        # Ancestor redact shadows an earlier child rule.
        rules = {"rules": [
            {"field": "meta.secret", "action": "hash", "length": 8},
            {"field": "meta", "action": "redact"},
        ]}
        masked, fields = masking.explain_record(record, rules)
        self.assertEqual({"a": 1, "meta": "***"}, masked)
        actions = {f["field"]: f["action"] for f in fields}
        self.assertEqual({"a": "keep", "meta": "redact"}, actions)

    def test_evidence_never_carries_raw_redacted_or_dropped_values(self):
        _, fields = masking.explain_record(RECORDS[0], RULES)
        blob = json.dumps(fields, ensure_ascii=False)
        self.assertNotIn("TOP-SECRET-TEXT", blob)
        self.assertNotIn("HAICE-01", blob)
        self.assertNotIn("31.230416", blob)  # pre-rounding value absent
        self.assertNotIn("42.51", blob)     # pre-redaction value absent


class BuildEvidenceTest(EvidenceTestBase):
    def test_verified_record_carries_frozen_summary_and_field_evidence(self):
        self.publish("E-1", RECORDS, RULES)
        payload = evidence.build_evidence(self.conn, "E-1", 0)
        self.assertEqual("verified", payload["status"])
        self.assertEqual(0, payload["record_index"])
        self.assertEqual(2, payload["record_count"])
        self.assertTrue(payload["artifact_digest_verified"])
        self.assertTrue(payload["replayed_from_frozen"])
        summary = payload["frozen_rules"]
        self.assertEqual(store.get_export(self.conn, "E-1")["rules_version"],
                         summary["rules_version"])
        self.assertEqual(4, summary["rule_count"])
        actions = {a["field"]: a["action"] for a in summary["actions"]}
        self.assertEqual({"depth_m": "redact", "lat": "round",
                          "vessel_id": "hash", "note": "drop"}, actions)
        self.assertEqual(payload["artifact_digest"],
                         store.get_export(self.conn, "E-1")["artifact_digest"])
        by_field = {f["field"]: f for f in payload["fields"]}
        self.assertEqual("***", payload["masked_record"]["depth_m"])
        self.assertEqual(31.23, by_field["lat"]["output"])

    def test_response_serialization_does_not_leak_raw_values(self):
        self.publish("E-1", RECORDS, RULES)
        payload = evidence.build_evidence(self.conn, "E-1", 1)
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("TOP-SECRET-TEXT", blob)
        self.assertNotIn("HAICE-01", blob)
        self.assertNotIn("31.231102", blob)
        self.assertNotIn("43.04", blob)

    def test_unknown_export_refused(self):
        exc = self.expect_refusal("NOPE", 0, "not_found")
        self.assertEqual(404, exc.status)

    def test_unpublished_export_refused(self):
        store.set_rules(self.conn, RULES)
        store.submit_export(self.conn, "E-0", RECORDS)
        exc = self.expect_refusal("E-0", 0, "not_published")
        self.assertEqual(409, exc.status)

    def test_index_bounds_refused_without_guessing(self):
        self.publish("E-1", RECORDS, RULES)
        exc = self.expect_refusal("E-1", 2, "index_out_of_range")
        self.assertEqual(404, exc.status)
        exc = self.expect_refusal("E-1", -1, "invalid_index")
        self.assertEqual(422, exc.status)

    def test_missing_artifact_refused(self):
        row = self.publish("E-1", RECORDS, RULES)
        os.unlink(row["artifact_path"])
        exc = self.expect_refusal("E-1", 0, "artifact_missing")
        self.assertEqual(410, exc.status)

    def test_corrupted_artifact_refused(self):
        row = self.publish("E-1", RECORDS, RULES)
        artifacts.tamper_published(row, "corrupt_artifact")
        exc = self.expect_refusal("E-1", 0, "artifact_unverified")
        self.assertEqual(410, exc.status)

    def test_frozen_input_tampering_triggers_replay_mismatch(self):
        self.publish("E-1", RECORDS, RULES)
        # The on-disk artifact still verifies against the recorded digest, but
        # the frozen input no longer reproduces it: no guess may be returned.
        tampered = json.dumps([dict(RECORDS[0], lat=99.9), RECORDS[1]])
        self.conn.execute("UPDATE exports SET records = ? WHERE export_id = 'E-1'", (tampered,))
        exc = self.expect_refusal("E-1", 0, "replay_mismatch")
        self.assertEqual(410, exc.status)

    def test_old_export_keeps_original_rules_snapshot_after_rules_change(self):
        self.publish("E-OLD", RECORDS, RULES)
        old = evidence.build_evidence(self.conn, "E-OLD", 0)
        old_digest = old["frozen_rules"]["rules_digest"]
        old_version = old["frozen_rules"]["rules_version"]

        rules_r2 = {"rules": [{"field": "lat", "action": "redact"}]}
        store.set_rules(self.conn, rules_r2)
        again = evidence.build_evidence(self.conn, "E-OLD", 0)
        self.assertEqual(old_digest, again["frozen_rules"]["rules_digest"])
        self.assertEqual(old_version, again["frozen_rules"]["rules_version"])
        actions = {a["field"]: a["action"] for a in again["frozen_rules"]["actions"]}
        self.assertIn("depth_m", actions)
        self.assertEqual(31.23, again["masked_record"]["lat"])  # still rounded, not redacted

        self.publish("E-NEW", RECORDS)
        fresh = evidence.build_evidence(self.conn, "E-NEW", 0)
        self.assertNotEqual(old_digest, fresh["frozen_rules"]["rules_digest"])
        self.assertEqual(old_version + 1, fresh["frozen_rules"]["rules_version"])
        self.assertEqual("***", fresh["masked_record"]["lat"])
        self.assertEqual(42.51, fresh["masked_record"]["depth_m"])  # kept under new snapshot


class EvidenceHttpTest(EvidenceTestBase):
    def setUp(self):
        super().setUp()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        super().tearDown()

    def _get(self, path):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, path), timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _post(self, path, body):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path), data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_evidence_endpoint_verified_and_refusals(self):
        self.publish("E-1", RECORDS, RULES)
        status, payload = self._get("/api/exports/E-1/evidence?index=1")
        self.assertEqual(200, status)
        self.assertEqual("verified", payload["status"])
        self.assertEqual(1, payload["record_index"])
        self.assertNotIn("HAICE-01", json.dumps(payload))

        status, payload = self._get("/api/exports/E-1/evidence?index=9")
        self.assertEqual(404, status)
        self.assertEqual("index_out_of_range", payload["error"])

        status, payload = self._get("/api/exports/E-1/evidence?index=x")
        self.assertEqual(422, status)
        self.assertEqual("invalid_index", payload["error"])

        status, payload = self._get("/api/exports/NOPE/evidence?index=0")
        self.assertEqual(404, status)
        self.assertEqual("not_found", payload["error"])

    def test_tamper_hook_disabled_by_default_then_refuses_corruption(self):
        self.publish("E-1", RECORDS, RULES)
        status, _ = self._post("/api/test/fault",
                               {"export_id": "E-1", "mode": "corrupt_artifact"})
        self.assertEqual(404, status)  # TEST_HOOKS not set in this run

        os.environ["TEST_HOOKS"] = "1"
        try:
            status, payload = self._post("/api/test/fault",
                                         {"export_id": "E-1", "mode": "corrupt_artifact"})
            self.assertEqual(202, status)
            self.assertEqual("corrupted", payload["result"])
        finally:
            os.environ.pop("TEST_HOOKS", None)

        status, payload = self._get("/api/exports/E-1/evidence?index=0")
        self.assertEqual(410, status)
        self.assertEqual("artifact_unverified", payload["error"])


if __name__ == "__main__":
    unittest.main()
