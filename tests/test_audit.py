"""Tests for the hash-chained audit log."""
from datetime import datetime, timezone

from airp.audit import AuditLog

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)


def test_append_chains_hashes_and_verify_passes():
    log = AuditLog()
    e1 = log.append("alice", "incident_detected", {"incident_id": "INC-0001"}, timestamp=T0)
    e2 = log.append("bob", "playbook_executed", {"incident_id": "INC-0001"}, timestamp=T0)
    assert e1.seq == 1
    assert e2.seq == 2
    assert e2.prev_hash == e1.entry_hash
    assert e1.prev_hash == "0" * 64
    assert log.verify()
    assert len(log) == 2


def test_verify_detects_tampered_payload():
    log = AuditLog()
    log.append("alice", "incident_detected", {"incident_id": "INC-0001"}, timestamp=T0)
    log.append("bob", "playbook_executed", {"incident_id": "INC-0001"}, timestamp=T0)
    # Tamper with the first entry's payload (dataclass is frozen, so use
    # object.__setattr__ to simulate an out-of-band edit).
    object.__setattr__(log.entries[0], "payload", '{"incident_id": "INC-9999"}')
    assert not log.verify()


def test_verify_detects_reordered_entries():
    log = AuditLog()
    log.append("alice", "a", {}, timestamp=T0)
    log.append("bob", "b", {}, timestamp=T0)
    entries = log._entries
    entries[0], entries[1] = entries[1], entries[0]
    assert not log.verify()


def test_for_incident_filters_by_payload():
    log = AuditLog()
    log.append("alice", "incident_detected", {"incident_id": "INC-0001"}, timestamp=T0)
    log.append("alice", "incident_detected", {"incident_id": "INC-0002"}, timestamp=T0)
    log.append("bob", "note", {"incident_id": "INC-0001"}, timestamp=T0)
    assert len(log.for_incident("INC-0001")) == 2
    assert len(log.for_incident("INC-0002")) == 1
    assert log.for_incident("INC-9999") == []


def test_empty_log_verifies():
    assert AuditLog().verify()
