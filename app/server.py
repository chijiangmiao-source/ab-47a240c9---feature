"""HTTP API + static page. Stdlib only: ThreadingHTTPServer.

Endpoints:
  GET  /healthz                        health response
  GET  /                               operator page (polls the real API)
  GET  /api/rules                      current masking rules + digest
  PUT  /api/rules                      replace masking rules
  POST /api/exports                    submit records under a stable export id
  GET  /api/exports                    list exports (stage, digests, receipt)
  GET  /api/exports/{id}               detail incl. journal + lease
  GET  /api/exports/{id}/artifact      download (only verified, published)
  GET  /api/exports/{id}/records/{n}/evidence  per-record replay evidence
  POST /api/test/fault                 fault injection (TEST_HOOKS=1 only)
"""
import hashlib
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import artifacts, config, evidence, masking, store
from .canonical import canonical

MAX_BODY = 1 << 20
MAX_RECORDS = 100
EXPORT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# TEST_HOOKS-only tampering with an already-published artifact, to prove the
# evidence/download paths refuse unverifiable or non-reproducible content.
ARTIFACT_FAULT_MODES = ("corrupt_artifact", "remove_artifact", "desync_artifact")

INDEX_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public", "index.html")


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _validate_submission(doc):
    if not isinstance(doc, dict):
        raise ApiError(422, "invalid_body", "request body must be a JSON object")
    export_id = doc.get("export_id")
    if not isinstance(export_id, str) or not EXPORT_ID_RE.match(export_id):
        raise ApiError(422, "invalid_export_id",
                       "export_id must match %s" % EXPORT_ID_RE.pattern)
    records = doc.get("records")
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise ApiError(422, "invalid_records",
                       "records must be an array of 1..%d objects" % MAX_RECORDS)
    for record in records:
        if not isinstance(record, dict):
            raise ApiError(422, "invalid_records", "each record must be a JSON object")
    return export_id, records


def _public_export(row):
    return {
        "export_id": row["export_id"],
        "stage": row["stage"],
        "input_digest": row["input_digest"],
        "rules_digest": row["rules_digest"],
        "rules_version": row["rules_version"],
        "artifact_digest": row["artifact_digest"],
        "receipt_id": row["receipt_id"],
        "received_at": row["received_at"],
        "published_at": row["published_at"],
        "attempts": row["attempts"],
        "updated_at": row["updated_at"],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "TrackExport/1.0"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ helpers
    def _send_json(self, status, payload, extra_headers=None):
        body = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status, code, message):
        self._send_json(status, {"error": code, "message": message})

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ApiError(400, "missing_body", "request body is required")
        if length > MAX_BODY:
            raise ApiError(413, "body_too_large", "body exceeds %d bytes" % MAX_BODY)
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(400, "invalid_json", "body is not valid JSON: %s" % exc)

    def log_message(self, fmt, *args):
        pass  # keep container logs focused on worker/app events

    # ------------------------------------------------------------ dispatch
    def do_GET(self):
        try:
            self._route_get(urlparse(self.path).path.rstrip("/") or "/")
        except ApiError as exc:
            self._send_error_json(exc.status, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - never leak a stack to clients
            self._send_error_json(500, "internal_error", repr(exc))

    def do_PUT(self):
        self._handle_mutation("PUT")

    def do_POST(self):
        self._handle_mutation("POST")

    def _handle_mutation(self, method):
        try:
            doc = self._read_json_body()
            self._route_mutation(method, urlparse(self.path).path.rstrip("/") or "/", doc)
        except ApiError as exc:
            self._send_error_json(exc.status, exc.code, exc.message)
        except ValueError as exc:
            self._send_error_json(422, "unprocessable", str(exc))
        except Exception as exc:  # noqa: BLE001
            self._send_error_json(500, "internal_error", repr(exc))

    # ------------------------------------------------------------ GET
    def _route_get(self, path):
        if path == "/healthz":
            self._send_json(200, {"ok": True, "ts": store.utcnow()})
            return
        if path == "/":
            self._serve_index()
            return
        if path == "/api/rules":
            conn = store.connect()
            try:
                rules = store.get_rules(conn)
            finally:
                conn.close()
            self._send_json(200, {
                "version": rules["version"],
                "digest": rules["digest"],
                "updated_at": rules["updated_at"],
                "rules": json.loads(rules["body"]),
            })
            return
        if path == "/api/exports":
            conn = store.connect()
            try:
                rows = store.list_exports(conn)
            finally:
                conn.close()
            self._send_json(200, {"exports": [_public_export(row) for row in rows]})
            return
        match = re.fullmatch(r"/api/exports/([A-Za-z0-9._-]+)", path)
        if match:
            self._get_export_detail(match.group(1))
            return
        match = re.fullmatch(r"/api/exports/([A-Za-z0-9._-]+)/artifact", path)
        if match:
            self._download_artifact(match.group(1))
            return
        match = re.fullmatch(r"/api/exports/([A-Za-z0-9._-]+)/records/(-?[0-9]+)/evidence", path)
        if match:
            self._get_record_evidence(match.group(1), match.group(2))
            return
        self._send_error_json(404, "not_found", "no such route: %s" % path)

    def _serve_index(self):
        try:
            with open(INDEX_HTML, "rb") as fh:
                body = fh.read()
        except FileNotFoundError:
            self._send_error_json(404, "not_found", "page not installed")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _get_export_detail(self, export_id):
        conn = store.connect()
        try:
            row = store.get_export(conn, export_id)
            if not row:
                self._send_error_json(404, "not_found", "unknown export_id: %s" % export_id)
                return
            payload = _public_export(row)
            payload["record_count"] = len(json.loads(row["records"]))
            payload["events"] = store.export_events(conn, export_id)
            lease = store.get_lease(conn, "export:" + export_id)
            payload["lease"] = lease
            payload["download_url"] = "/api/exports/%s/artifact" % export_id
        finally:
            conn.close()
        self._send_json(200, payload)

    def _download_artifact(self, export_id):
        conn = store.connect()
        try:
            row = store.get_export(conn, export_id)
        finally:
            conn.close()
        if not row:
            self._send_error_json(404, "not_found", "unknown export_id: %s" % export_id)
            return
        if row["stage"] != "PUBLISHED":
            self._send_error_json(409, "not_published",
                                  "export is in stage %s; artifact not downloadable yet" % row["stage"])
            return
        try:
            data = artifacts.load_verified(row)
        except artifacts.ArtifactMissing:
            self._send_error_json(410, "artifact_missing", "published artifact file is gone")
            return
        except artifacts.DigestMismatch:
            self._send_error_json(500, "artifact_unverified",
                                  "artifact failed digest verification; refusing to serve")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="%s.json"' % export_id)
        self.send_header("X-Artifact-Digest", row["artifact_digest"])
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _get_record_evidence(self, export_id, index_str):
        conn = store.connect()
        try:
            row = store.get_export(conn, export_id)
        finally:
            conn.close()
        if not row:
            self._send_error_json(404, "not_found", "unknown export_id: %s" % export_id)
            return
        try:
            payload = evidence.record_evidence(row, int(index_str))
        except evidence.EvidenceError as exc:
            self._send_error_json(exc.status, exc.code, exc.message)
            return
        except artifacts.ArtifactMissing:
            self._send_error_json(410, "artifact_missing", "published artifact file is gone")
            return
        except artifacts.DigestMismatch:
            self._send_error_json(500, "artifact_unverified",
                                  "artifact failed digest verification; refusing to serve evidence")
            return
        self._send_json(200, payload)

    # ------------------------------------------------------------ PUT/POST
    def _route_mutation(self, method, path, doc):
        if method == "PUT" and path == "/api/rules":
            errors = masking.validate_rules(doc)
            if errors:
                raise ApiError(422, "invalid_rules", "; ".join(errors))
            conn = store.connect()
            try:
                rules = store.set_rules(conn, doc)
            finally:
                conn.close()
            self._send_json(200, {
                "version": rules["version"],
                "digest": rules["digest"],
                "updated_at": rules["updated_at"],
                "rules": json.loads(rules["body"]),
            })
            return
        if method == "POST" and path == "/api/exports":
            export_id, records = _validate_submission(doc)
            conn = store.connect()
            try:
                status, payload = store.submit_export(conn, export_id, records)
            finally:
                conn.close()
            self._send_json(status, payload)
            return
        if method == "POST" and path == "/api/test/fault":
            if not config.test_hooks():
                self._send_error_json(404, "not_found", "test hooks disabled")
                return
            export_id = doc.get("export_id")
            mode = doc.get("mode")
            if not isinstance(export_id, str):
                raise ApiError(422, "invalid_fault", "need export_id")
            if mode in ARTIFACT_FAULT_MODES:
                self._apply_artifact_fault(export_id, mode)
                self._send_json(202, {"ok": True, "export_id": export_id, "mode": mode})
                return
            if mode not in store.FAULT_MODES:
                raise ApiError(422, "invalid_fault",
                               "need export_id and mode in %s"
                               % "/".join(store.FAULT_MODES + ARTIFACT_FAULT_MODES))
            conn = store.connect()
            try:
                store.set_fault(conn, export_id, mode)
            finally:
                conn.close()
            self._send_json(202, {"ok": True, "export_id": export_id, "mode": mode})
            return
        self._send_error_json(404, "not_found", "no such route: %s %s" % (method, path))

    def _apply_artifact_fault(self, export_id, mode):
        """TEST_HOOKS only: tamper with a published artifact so acceptance can
        prove the evidence/download paths refuse bad content."""
        conn = store.connect()
        try:
            row = store.get_export(conn, export_id)
            if not row:
                raise ApiError(404, "not_found", "unknown export_id: %s" % export_id)
            if row["stage"] != "PUBLISHED" or not row["artifact_path"]:
                raise ApiError(409, "not_published", "artifact faults require a published export")
            path = row["artifact_path"]
            if mode == "corrupt_artifact":
                if not os.path.exists(path):
                    raise ApiError(409, "artifact_missing", "artifact file already gone")
                with open(path, "ab") as fh:
                    fh.write(b"\ntampered")
                    fh.flush()
                    os.fsync(fh.fileno())
                detail = "appended bytes to %s" % path
            elif mode == "remove_artifact":
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    raise ApiError(409, "artifact_missing", "artifact file already gone")
                detail = "removed %s" % path
            else:  # desync_artifact: valid JSON, digest-consistent, but not reproducible
                data = artifacts.load_verified(row)
                doc = json.loads(data.decode("utf-8"))
                doc["records"][0]["__desync__"] = True
                body = (canonical(doc) + "\n").encode("utf-8")
                with open(path, "wb") as fh:
                    fh.write(body)
                    fh.flush()
                    os.fsync(fh.fileno())
                digest = hashlib.sha256(body).hexdigest()
                store.force_artifact_digest(conn, export_id, digest)
                detail = "rewrote %s and forced digest %s" % (path, digest)
            store.journal(conn, export_id, "api", "fault_artifact_" + mode, detail)
        finally:
            conn.close()


def main():
    config.ensure_dirs()
    conn = store.connect()
    try:
        store.init_db(conn)
    finally:
        conn.close()
    server = ThreadingHTTPServer(("0.0.0.0", config.port()), Handler)
    print("track-export API listening on :%d" % config.port(), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
