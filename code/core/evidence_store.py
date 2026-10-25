"""Evidence store module.
Parses, indexes, and queries point-in-time evidence files from dataset/evidence/
(SQL snapshot dumps, JSON records, structured logs, and text handovers).
"""
import os
import re
import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Set, Optional, Any
from pypdf import PdfReader

from code.models import (
    IdentityEnvelope, DiscoveredResource, ResourceState, Operation
)

class EvidenceObservation:
    def __init__(
        self,
        file_id: str,
        captured_at: str,
        system_id: str,
        resource_id: str,
        category: str,
        state: ResourceState,
        matched_keys: Set[str],
        has_exposed_pii: bool = False,
        is_retained: bool = False,
        details: Optional[Dict[str, Any]] = None
    ):
        self.file_id = file_id
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.category = category
        self.state = state
        self.matched_keys = {k.strip().lower() for k in matched_keys if k}
        self.has_exposed_pii = has_exposed_pii
        self.is_retained = is_retained
        self.details = details or {}

def infer_category(sys_id: str, res_id: str, coll: str = "") -> str:
    """Infers policy-defined category from system ID, resource ID, and collection name."""
    res_lower = res_id.lower()
    sys_lower = sys_id.lower()
    coll_lower = coll.lower()

    if "tombstone" in res_lower or "identity" in sys_lower:
        return "ACCOUNT_TOMBSTONE"
    if "export" in res_lower or "export" in sys_lower or "export" in coll_lower:
        return "USER_EXPORT"
    if "audit" in res_lower or "security" in sys_lower:
        return "SECURITY_AUDIT_LOG"
    if "backup" in res_lower or "backup" in sys_lower:
        return "BACKUP_ARCHIVE"
    if "flow" in res_lower or "integration" in sys_lower or "connector" in coll_lower:
        return "DATA_FLOW"
    if "attachment" in res_lower or "attachment" in coll_lower:
        return "SUPPORT_ATTACHMENT"
    if "support" in res_lower or "support" in sys_lower or "ticket" in coll_lower:
        return "SUPPORT_MESSAGE"
    if "legal" in res_lower or "legal" in sys_lower:
        return "LEGAL_HOLD_RECORD"
    if "search" in res_lower or "search" in sys_lower:
        return "SEARCH_INDEX_ENTRY"
    if "analytics" in res_lower or "analytics" in sys_lower or "telemetry" in coll_lower:
        return "ANALYTICS_PROFILE"
    if "marketing" in res_lower or "marketing" in sys_lower or "campaign" in coll_lower:
        return "MARKETING_PROFILE"
    if "delivery" in res_lower or "delivery" in sys_lower:
        return "EMAIL_DELIVERY_LOG"
    if "cache" in res_lower or "cache" in sys_lower:
        return "CACHE_ENTRY"
    if "secondary" in res_lower or "alias" in coll_lower:
        return "SECONDARY_IDENTIFIER"
    return "USER_PROFILE"

class EvidenceStore:
    def __init__(self, dataset_dir: Path, manifest: List[Dict[str, str]]):
        self.dataset_dir = dataset_dir
        self.manifest_by_file_id: Dict[str, Dict[str, str]] = {
            m["file_id"]: m for m in manifest
        }
        self.observations: List[EvidenceObservation] = []
        self._index_all_evidence()

    def has_evidence(self, file_id: str, cutoff_time: Optional[str] = None) -> bool:
        """Checks if a given file_id exists in manifest and was captured at or before cutoff_time."""
        m = self.manifest_by_file_id.get(file_id)
        if not m:
            return False
        if cutoff_time and m.get("captured_at", "") > cutoff_time:
            return False
        return True

    def _index_all_evidence(self) -> None:
        """Parses and indexes all participant-visible evidence files."""
        for file_id, m in self.manifest_by_file_id.items():
            rel_path = m["file_path"]
            captured_at = m["captured_at"]
            abs_path = self.dataset_dir / rel_path

            if not abs_path.exists():
                continue

            try:
                if rel_path.endswith(".txt"):
                    self._parse_handover_txt(file_id, captured_at, abs_path)
                elif rel_path.endswith(".json"):
                    self._parse_json_record(file_id, captured_at, abs_path)
                elif rel_path.endswith(".sql"):
                    self._parse_sql_dump(file_id, captured_at, abs_path)
                elif rel_path.endswith(".log"):
                    self._parse_log_file(file_id, captured_at, abs_path)
                elif rel_path.endswith(".pdf"):
                    self._parse_pdf_doc(file_id, captured_at, abs_path)
            except Exception as e:
                # Fault isolation: corrupt or unparseable evidence doesn't crash the indexer
                continue

    def _parse_handover_txt(self, file_id: str, captured_at: str, path: Path) -> None:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip().lstrip("- ")
                if not line or line.startswith("#") or "|" not in line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 6:
                    # Format: timestamp | system | resource_id | category | status | key
                    _, sys_id, res_id, cat, status, key = parts[:6]
                    state = ResourceState.PRESENT
                    has_pii = False
                    if status in ["NOT_FOUND", "ABSENT", "DELETED"]:
                        state = ResourceState.ABSENT
                    elif status in ["FOUND", "PRESENT"]:
                        state = ResourceState.PRESENT
                    elif status in ["IDENTIFIABLE", "EXPOSED"]:
                        state = ResourceState.PRESENT
                        has_pii = True
                    elif status == "ACTIVE":
                        state = ResourceState.ACTIVE
                    elif status == "DISABLED":
                        state = ResourceState.DISABLED
                    elif status == "BLOCKED":
                        state = ResourceState.BLOCKED

                    self.observations.append(EvidenceObservation(
                        file_id=file_id,
                        captured_at=captured_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        category=cat,
                        state=state,
                        matched_keys={key},
                        has_exposed_pii=has_pii,
                        is_retained=(cat == "SECURITY_AUDIT_LOG")
                    ))

    def _parse_json_record(self, file_id: str, captured_at: str, path: Path) -> None:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        # 1. service_resource_export_*.json
        if "service_exports" in data:
            exports = data["service_exports"]
            for sys_id, subdict in exports.items():
                for subkey, items in subdict.items():
                    for item in items:
                        res_id = item.get("resource_id", "")
                        if not res_id:
                            continue
                        keys: Set[str] = {res_id}
                        for k in ["customer_reference", "subject_reference", "user_id", "email", "phone", "email_hash", "lookup_key", "customer_email", "owner_email", "query", "requester_email", "requester_phone", "requester_name", "display_name"]:
                            val = item.get(k)
                            if val and isinstance(val, str):
                                keys.add(val)

                        # Check nested profile in account_service
                        if isinstance(item.get("profile"), dict):
                            prof = item["profile"]
                            for k in ["customer_reference", "subject_reference", "user_id", "email", "phone", "email_hash", "full_name"]:
                                val = prof.get(k)
                                if val and isinstance(val, str):
                                    keys.add(val)

                        # Check nested hits for search queries
                        if "hits" in item and isinstance(item["hits"], dict):
                            for doc in item["hits"].get("documents", []):
                                for k in ["email", "phone", "customer_reference", "requester_email"]:
                                    v = doc.get(k)
                                    if v and isinstance(v, str): keys.add(v)

                        state = ResourceState.PRESENT
                        has_pii = False
                        cat = "USER_PROFILE"

                        if sys_id == "account_service":
                            cat = "USER_PROFILE"
                            status_code = item.get("status_code", item.get("http_status"))
                            if status_code == 404 or item.get("profile") is None:
                                state = ResourceState.ABSENT
                        elif sys_id == "search_service":
                            cat = "SEARCH_INDEX_ENTRY"
                            hits_total = item.get("hits", {}).get("total", 0) if isinstance(item.get("hits"), dict) else 0
                            state = ResourceState.PRESENT if hits_total > 0 else ResourceState.ABSENT
                        elif sys_id == "analytics_platform":
                            cat = "ANALYTICS_PROFILE"
                            is_attr = any(item.get(k) for k in ["email", "phone", "email_hash", "customer_reference"])
                            if not is_attr:
                                state = ResourceState.ANONYMIZED
                            else:
                                state = ResourceState.PRESENT
                                has_pii = True
                        elif sys_id == "support_platform":
                            cat = "SUPPORT_MESSAGE"
                            is_attr = any(item.get(k) for k in ["requester_email", "requester_phone", "requester_name"])
                            if not is_attr:
                                state = ResourceState.REDACTED
                            else:
                                state = ResourceState.PRESENT
                                has_pii = True
                        elif sys_id == "integration_service":
                            cat = "DATA_FLOW"
                            enabled = item.get("enabled", False)
                            state = ResourceState.ACTIVE if enabled else ResourceState.DISABLED
                        elif sys_id == "backup_service":
                            cat = "BACKUP_ARCHIVE"
                            restore_allowed = item.get("restore_allowed", False)
                            state = ResourceState.ACTIVE if restore_allowed else ResourceState.BLOCKED
                        elif sys_id == "security_service":
                            cat = "SECURITY_AUDIT_LOG"
                            state = ResourceState.PRESENT
                        elif sys_id == "export_service":
                            cat = "USER_EXPORT"
                            state = ResourceState.PRESENT
                        elif sys_id == "identity_service":
                            cat = "ACCOUNT_TOMBSTONE"
                            state = ResourceState.PRESENT

                        if keys:
                            self.observations.append(EvidenceObservation(
                                file_id=file_id,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                category=cat,
                                state=state,
                                matched_keys=keys,
                                has_exposed_pii=has_pii,
                                is_retained=(cat == "SECURITY_AUDIT_LOG")
                            ))

        # 2. customer_data_snapshot_bundle_*.json
        elif "snapshots" in data:
            for s in data["snapshots"]:
                sys_id = s.get("data_store", s.get("system_id", ""))
                coll = s.get("collection", "")
                for rec in s.get("records", []):
                    res_id = rec.get("resource_id", "")
                    if not res_id:
                        continue
                    keys = set()
                    for k in ["customer_reference", "subject_reference", "user_id", "email", "phone", "email_hash", "owner_email", "requester_email", "requester_phone", "requester_name"]:
                        val = rec.get(k)
                        if val and isinstance(val, str):
                            keys.add(val)

                    state = ResourceState.PRESENT
                    has_pii = False
                    cat = infer_category(sys_id, res_id, coll)

                    if sys_id == "identity_service" or "tombstone" in res_id:
                        cat = "ACCOUNT_TOMBSTONE"
                        has_pii = any(rec.get(k) for k in ["name", "email", "phone", "email_hash"])
                        state = ResourceState.REDACTED if not has_pii else ResourceState.PRESENT
                    elif sys_id == "security_service":
                        cat = "SECURITY_AUDIT_LOG"
                        state = ResourceState.PRESENT
                    elif sys_id == "support_platform" or "support" in sys_id:
                        if "attachment" in coll or "attachment" in res_id:
                            cat = "SUPPORT_ATTACHMENT"
                            state = ResourceState.PRESENT
                        else:
                            cat = "SUPPORT_MESSAGE"
                            has_pii = any(rec.get(k) for k in ["requester_email", "requester_phone", "requester_name", "email", "phone"])
                            state = ResourceState.PRESENT if has_pii else ResourceState.REDACTED
                    elif sys_id == "export_service":
                        cat = "USER_EXPORT"
                        state = ResourceState.PRESENT
                    elif sys_id == "analytics_platform":
                        cat = "ANALYTICS_PROFILE"
                        has_pii = any(rec.get(k) for k in ["email", "phone", "email_hash", "customer_reference"])
                        state = ResourceState.PRESENT if has_pii else ResourceState.ANONYMIZED

                    if keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=res_id,
                            category=cat,
                            state=state,
                            matched_keys=keys,
                            has_exposed_pii=has_pii,
                            is_retained=(cat == "SECURITY_AUDIT_LOG")
                        ))

        # 3. Records lists: manifests, ledgers, connector configs, and analytics reports
        elif "records" in data:
            coll = data.get("collection", "")
            for rec in data.get("records", []):
                res_id = rec.get("resource_id", "")
                if not res_id:
                    continue
                keys = set()
                for k in ["customer_reference", "subject_reference", "user_id", "email", "phone", "email_hash", "owner_email", "requester_email"]:
                    val = rec.get(k)
                    if val and isinstance(val, str):
                        keys.add(val)

                raw_sys = rec.get("system", "")
                sys_id = raw_sys or "export_service"
                if "analytics" in coll or "analytics" in res_id:
                    sys_id = "analytics_platform"
                elif "search" in res_id or "search" in raw_sys:
                    sys_id = "search_service"
                elif "support" in res_id or "support" in raw_sys:
                    sys_id = "support_platform"
                elif "account" in res_id or "account" in raw_sys:
                    sys_id = "account_service"
                elif "security" in raw_sys or "audit" in res_id:
                    sys_id = "security_service"

                result = rec.get("result", "")
                state = ResourceState.PRESENT
                if result == "NOT_FOUND":
                    state = ResourceState.ABSENT
                elif result == "FOUND":
                    state = ResourceState.PRESENT

                cat = rec.get("record_type") or infer_category(sys_id, res_id, coll)
                if coll == "customer_analytics_reports":
                    cat = "ANALYTICS_PROFILE"
                    sys_id = "analytics_platform"
                    has_pii = any(rec.get(k) for k in ["user_id", "email", "phone", "email_hash"])
                    state = ResourceState.PRESENT if has_pii else ResourceState.ANONYMIZED
                    keys.add(res_id)  # analytics_901
                
                self.observations.append(EvidenceObservation(
                    file_id=file_id,
                    captured_at=captured_at,
                    system_id=sys_id,
                    resource_id=res_id,
                    category=cat,
                    state=state,
                    matched_keys=keys,
                    has_exposed_pii=False,
                    is_retained=(cat == "SECURITY_AUDIT_LOG" or sys_id == "security_service")
                ))

    def _parse_sql_dump(self, file_id: str, captured_at: str, path: Path) -> None:
        conn = sqlite3.connect(":memory:")
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            script = f.read()
        conn.executescript(script)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]

        for t in tables:
            cur.execute(f"PRAGMA table_info({t});")
            cols = [r[1] for r in cur.fetchall()]
            
            # Check for record_json table format
            if "record_json" in cols and "resource_id" in cols:
                cur.execute(f"SELECT resource_id, origin_system, collection_name, record_json FROM {t};")
                for res_id, orig_sys, coll, r_json in cur.fetchall():
                    try:
                        rec = json.loads(r_json) if isinstance(r_json, str) else {}
                    except Exception:
                        rec = {}
                    keys = set()
                    for k in ["customer_reference", "subject_reference", "user_id", "email", "phone", "email_hash", "owner_email", "requester_email"]:
                        val = rec.get(k)
                        if val and isinstance(val, str):
                            keys.add(val)
                    if not keys:
                        continue
                    
                    sys_id = orig_sys or "account_service"
                    cat = infer_category(sys_id, res_id, coll)
                    state = ResourceState.PRESENT
                    has_pii = False
                    
                    if "profile" in coll or "account" in sys_id:
                        cat = "USER_PROFILE"
                        sys_id = "account_service"
                    elif "search" in coll or "search" in sys_id:
                        cat = "SEARCH_INDEX_ENTRY"
                        sys_id = "search_service"
                    elif "analytics" in coll or "analytics" in sys_id:
                        cat = "ANALYTICS_PROFILE"
                        sys_id = "analytics_platform"
                    elif "support" in coll or "support" in sys_id:
                        cat = "SUPPORT_MESSAGE"
                        sys_id = "support_platform"
                    elif "export" in coll or "export" in sys_id:
                        cat = "USER_EXPORT"
                        sys_id = "export_service"
                        
                    self.observations.append(EvidenceObservation(
                        file_id=file_id,
                        captured_at=captured_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        category=cat,
                        state=state,
                        matched_keys=keys,
                        has_exposed_pii=has_pii,
                        is_retained=False
                    ))
            
            # Check structured table schemas
            elif "customer_profiles" in t:
                cur.execute(f"SELECT * FROM {t};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    keys = {str(row_dict.get(k)) for k in ["customer_reference", "user_id", "email", "phone", "email_hash"] if row_dict.get(k)}
                    if res_id and keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id="account_service",
                            resource_id=res_id,
                            category="USER_PROFILE",
                            state=ResourceState.PRESENT,
                            matched_keys=keys
                        ))
            
            elif "search" in t:
                cur.execute(f"SELECT * FROM {t};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    keys = {str(row_dict.get(k)) for k in ["customer_reference", "email", "phone", "email_hash", "source_resource_id"] if row_dict.get(k)}
                    if res_id and keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id="search_service",
                            resource_id=res_id,
                            category="SEARCH_INDEX_ENTRY",
                            state=ResourceState.PRESENT,
                            matched_keys=keys
                        ))
                        
            elif "backup" in t:
                cur.execute(f"SELECT * FROM {t};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    keys = {str(row_dict.get(k)) for k in ["customer_reference", "customer_email"] if row_dict.get(k)}
                    allowed = str(row_dict.get("restore_allowed", "")).lower() in ["1", "true"]
                    if res_id and keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id="backup_service",
                            resource_id=res_id,
                            category="BACKUP_ARCHIVE",
                            state=ResourceState.ACTIVE if allowed else ResourceState.BLOCKED,
                            matched_keys=keys
                        ))
                        
            elif "support" in t:
                cur.execute(f"SELECT * FROM {t};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    keys = {str(row_dict.get(k)) for k in ["customer_reference", "requester_email", "requester_phone"] if row_dict.get(k)}
                    if res_id and keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id="support_platform",
                            resource_id=res_id,
                            category="SUPPORT_MESSAGE",
                            state=ResourceState.PRESENT,
                            matched_keys=keys,
                            has_exposed_pii=True
                        ))
                        
            elif "export" in t:
                cur.execute(f"SELECT * FROM {t};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    keys = {str(row_dict.get(k)) for k in ["customer_reference", "owner_email", "owner_phone"] if row_dict.get(k)}
                    if res_id and keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id="export_service",
                            resource_id=res_id,
                            category="USER_EXPORT",
                            state=ResourceState.PRESENT,
                            matched_keys=keys
                        ))
                        
            elif "connector" in t or "integration" in t:
                cur.execute(f"SELECT * FROM {t};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    keys = {str(row_dict.get(k)) for k in ["customer_reference", "customer_email"] if row_dict.get(k)}
                    enabled = str(row_dict.get("enabled", "")).lower() in ["1", "true"]
                    if res_id and keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id="integration_service",
                            resource_id=res_id,
                            category="DATA_FLOW",
                            state=ResourceState.ACTIVE if enabled else ResourceState.DISABLED,
                            matched_keys=keys
                        ))

            elif "security" in t or "audit" in t:
                cur.execute(f"SELECT * FROM {t};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    keys = {str(row_dict.get(k)) for k in ["subject_reference", "customer_reference"] if row_dict.get(k)}
                    if res_id and keys:
                        self.observations.append(EvidenceObservation(
                            file_id=file_id,
                            captured_at=captured_at,
                            system_id="security_service",
                            resource_id=res_id,
                            category="SECURITY_AUDIT_LOG",
                            state=ResourceState.PRESENT,
                            matched_keys=keys,
                            is_retained=True
                        ))

        conn.close()

    def _parse_log_file(self, file_id: str, captured_at: str, path: Path) -> None:
        def is_val(v: Optional[str]) -> bool:
            return bool(v and v.strip() and v.strip().lower() != "null")

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            last_lookup: Dict[str, str] = {}
            for line in f:
                line = line.strip()
                if not line:
                    continue

                matches = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line)
                clean_kvs = {k: (v1 if v1 != '' else v2) for k, v1, v2 in matches}
                
                raw_service = clean_kvs.get("service", "")
                res_id = clean_kvs.get("resource_id", "")
                trace_id = clean_kvs.get("trace_id", "")
                evt = clean_kvs.get("event", "")
                
                if is_val(clean_kvs.get("lookup_key")) and trace_id:
                    last_lookup[trace_id] = clean_kvs["lookup_key"]

                # Diagnostic start lines are intermediate traces, not final outcomes
                if evt.endswith("_started"):
                    continue

                keys = set()
                for k in ["customer_reference", "subject_reference", "lookup_key", "email", "requester_email", "customer_email", "correlation_key"]:
                    v = clean_kvs.get(k)
                    if is_val(v):
                        keys.add(v)
                if trace_id in last_lookup:
                    keys.add(last_lookup[trace_id])

                if not (raw_service and res_id):
                    continue

                service = raw_service
                if raw_service.startswith("account"): service = "account_service"
                elif raw_service.startswith("search"): service = "search_service"
                elif raw_service.startswith("analytics"): service = "analytics_platform"
                elif raw_service.startswith("support"): service = "support_platform"
                elif raw_service.startswith("integration"): service = "integration_service"
                elif raw_service.startswith("backup"): service = "backup_service"
                elif raw_service.startswith("security"): service = "security_service"
                elif raw_service.startswith("export"): service = "export_service"
                elif raw_service.startswith("identity"): service = "identity_service"

                state = ResourceState.PRESENT
                has_pii = False
                cat = "GENERAL"

                if service == "account_service":
                    cat = "USER_PROFILE"
                    if clean_kvs.get("http_status") == "404" or clean_kvs.get("rows") == "0":
                        state = ResourceState.ABSENT
                elif service == "search_service":
                    cat = "SEARCH_INDEX_ENTRY"
                    result = clean_kvs.get("result", "")
                    state = ResourceState.PRESENT if result == "hit" else ResourceState.ABSENT
                elif service == "analytics_platform":
                    cat = "ANALYTICS_PROFILE"
                    is_attr = any(is_val(clean_kvs.get(k)) for k in ["email", "phone", "email_hash", "correlation_key", "customer_reference"])
                    state = ResourceState.PRESENT if is_attr else ResourceState.ANONYMIZED
                    has_pii = is_attr
                elif service == "support_platform":
                    cat = "SUPPORT_MESSAGE"
                    marker_found = clean_kvs.get("marker_found", "").lower()
                    if marker_found == "false":
                        state = ResourceState.PRESENT
                        has_pii = True
                    else:
                        is_attr = any(is_val(clean_kvs.get(k)) for k in ["requester_email", "requester_phone", "requester_name"])
                        state = ResourceState.PRESENT if is_attr else ResourceState.REDACTED
                        has_pii = is_attr
                elif service == "integration_service":
                    cat = "DATA_FLOW"
                    enabled = clean_kvs.get("enabled", "").lower() == "true"
                    state = ResourceState.ACTIVE if enabled else ResourceState.DISABLED
                elif service == "backup_service":
                    cat = "BACKUP_ARCHIVE"
                    allowed = clean_kvs.get("restore_allowed", "").lower() == "true"
                    state = ResourceState.ACTIVE if allowed else ResourceState.BLOCKED
                elif service == "security_service":
                    cat = "SECURITY_AUDIT_LOG"
                    state = ResourceState.PRESENT
                elif service == "identity_service":
                    cat = "ACCOUNT_TOMBSTONE"
                    has_pii = any(is_val(clean_kvs.get(k)) for k in ["name", "email", "phone", "email_hash"])
                    state = ResourceState.PRESENT if has_pii else ResourceState.REDACTED
                elif service == "export_service":
                    cat = "USER_EXPORT"
                    state = ResourceState.PRESENT
                elif service == "legal_service":
                    cat = "LEGAL_HOLD_RECORD"
                    state = ResourceState.PRESENT
                elif service == "downstream_delivery_service":
                    cat = "EMAIL_DELIVERY_LOG"
                    state = ResourceState.PRESENT

                # Safe fallback mapping based on resource prefix
                if cat == "GENERAL":
                    if "tombstone" in res_id:
                        cat = "ACCOUNT_TOMBSTONE"
                    elif "export" in res_id:
                        cat = "USER_EXPORT"
                    elif "audit" in res_id:
                        cat = "SECURITY_AUDIT_LOG"
                    elif "backup" in res_id:
                        cat = "BACKUP_ARCHIVE"
                    elif "flow" in res_id:
                        cat = "DATA_FLOW"
                    elif "support" in res_id:
                        cat = "SUPPORT_MESSAGE"
                    elif "legal" in res_id:
                        cat = "LEGAL_HOLD_RECORD"
                    elif "account" in res_id:
                        cat = "USER_PROFILE"
                    elif "search" in res_id:
                        cat = "SEARCH_INDEX_ENTRY"
                    elif "analytics" in res_id:
                        cat = "ANALYTICS_PROFILE"
                    elif "marketing" in res_id:
                        cat = "MARKETING_PROFILE"
                    else:
                        cat = "USER_PROFILE"

                self.observations.append(EvidenceObservation(
                    file_id=file_id,
                    captured_at=captured_at,
                    system_id=service,
                    resource_id=res_id,
                    category=cat,
                    state=state,
                    matched_keys=keys,
                    has_exposed_pii=has_pii,
                    is_retained=(cat == "SECURITY_AUDIT_LOG")
                ))

    def _parse_pdf_doc(self, file_id: str, captured_at: str, path: Path) -> None:
        reader = PdfReader(path)
        text = "\n".join([page.extract_text() or "" for page in reader.pages])

        # Extract emails, user IDs, phones, and resource references dynamically
        emails = [e.lower() for e in re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)]
        uids = [u.lower() for u in re.findall(r"\buser_\d+\b", text)]
        phones = [re.sub(r"[^\d+]", "", p) for p in re.findall(r"\+?\d[\d\s-]{7,}\d", text) if re.sub(r"[^\d+]", "", p)]
        
        matched_keys = set(emails + uids + phones)

        # Support document attachments
        if "delivery_correction" in path.name or "support" in path.name:
            match = re.search(r"support_\d+", text)
            res_id = match.group(0) if match else "support_attachment"
            self.observations.append(EvidenceObservation(
                file_id=file_id,
                captured_at=captured_at,
                system_id="support_platform",
                resource_id=res_id,
                category="SUPPORT_ATTACHMENT",
                state=ResourceState.PRESENT,
                matched_keys=matched_keys,
                has_exposed_pii=bool(emails or phones),
                details={"emails": emails, "phones": phones, "user_ids": uids}
            ))
        elif "account_history" in path.name or "statement" in path.name:
            match = re.search(r"statement\s+([A-Za-z0-9_-]+)", text, re.IGNORECASE)
            res_id = match.group(1) if match else "customer_statement"
            self.observations.append(EvidenceObservation(
                file_id=file_id,
                captured_at=captured_at,
                system_id="account_service",
                resource_id=res_id,
                category="USER_EXPORT",
                state=ResourceState.PRESENT,
                matched_keys=matched_keys,
                has_exposed_pii=bool(emails or phones),
                details={"emails": emails, "phones": phones, "user_ids": uids}
            ))
        elif "security_retention" in path.name or "compliance" in path.name:
            match = re.search(r"audit_record_\d+", text)
            res_id = match.group(0) if match else "security_audit_log"
            self.observations.append(EvidenceObservation(
                file_id=file_id,
                captured_at=captured_at,
                system_id="security_service",
                resource_id=res_id,
                category="SECURITY_AUDIT_LOG",
                state=ResourceState.PRESENT,
                matched_keys=matched_keys,
                has_exposed_pii=False,
                is_retained=True,
                details={"user_ids": uids}
            ))

    def query_subject_observations(
        self, 
        identity: IdentityEnvelope, 
        audit_at: str,
        additional_resource_ids: Optional[Set[str]] = None
    ) -> List[EvidenceObservation]:
        """Queries all observations matching the subject envelope up to audit_at."""
        all_keys = {identity.user_id.lower()}
        for em in identity.emails:
            all_keys.add(em.lower())
        for ph in identity.phones:
            all_keys.add(ph.lower())
        for h in identity.email_hashes:
            all_keys.add(h.lower())

        extra_res = additional_resource_ids or set()
        id_emails = {em.lower() for em in identity.emails}
        id_phones = {ph.lower() for ph in identity.phones}

        matched: List[EvidenceObservation] = []
        for obs in self.observations:
            # Enforce strict temporal cutoff
            if obs.captured_at > audit_at:
                continue

            # If observation explicitly identifies a different user_id, isolate it
            obs_subjects = {k.lower() for k in obs.matched_keys if k.lower().startswith("user_")}
            if obs_subjects and identity.user_id.lower() not in obs_subjects:
                continue

            # Cross-subject email isolation
            obs_emails = {k.lower() for k in obs.matched_keys if "@" in k}
            if obs_emails and id_emails and not obs_emails.intersection(id_emails):
                continue

            # Cross-subject phone isolation
            obs_phones = {k.lower() for k in obs.matched_keys if any(c.isdigit() for c in k) and ("+" in k or "-" in k)}
            if obs_phones and id_phones and not obs_phones.intersection(id_phones):
                continue

            # Check if any key matches or resource_id is known target
            if obs.matched_keys.intersection(all_keys) or (obs.resource_id in extra_res):
                matched.append(obs)

        return matched
