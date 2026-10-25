"""Data loading and schema validation module.
Treats all dataset files as untrusted tabular input, enforces schema checks,
tracks duplicate records, and attaches source provenance to every loaded entity.
"""
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from code.models import (
    DeletionRule, DeletionCase, UserIdentityRecord,
    UserAuditLogRecord, SystemActivityRecord, EvidenceFileRecord,
    SourceProvenance
)
from code.core.errors import MissingFileError, MalformedRowError
from code.core.schema_validator import SchemaValidator
from code.core.logging_utils import get_logger

logger = get_logger("DataLoader")

class DataLoader:
    """Robust, schema-validating loader for all project datasets."""

    @staticmethod
    def _check_file_exists(path: Path) -> None:
        if not path.exists():
            raise MissingFileError(f"Target dataset file not found: {path}", {"path": str(path)})

    @classmethod
    def load_deletion_rules(cls, rules_path: Path) -> List[DeletionRule]:
        cls._check_file_exists(rules_path)
        rules: List[DeletionRule] = []
        seen_ids: Set[str] = set()

        with open(rules_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise MalformedRowError(f"Empty or corrupted CSV header in {rules_path}")
            SchemaValidator.validate_header("deletion_rules", reader.fieldnames, str(rules_path))

            for row_no, row in enumerate(reader, start=2):
                if not row or all(v is None or v.strip() == "" for v in row.values()):
                    continue
                SchemaValidator.validate_deletion_rule_row(row, row_no, str(rules_path), seen_ids)
                
                provenance = SourceProvenance(
                    source_file=str(rules_path),
                    row_number=row_no,
                    entity_id=row["rule_id"].strip()
                )
                rules.append(DeletionRule(
                    rule_id=row["rule_id"].strip(),
                    data_category=row["data_category"].strip(),
                    condition=row["condition"].strip(),
                    required_action=row["required_action"].strip().upper(),
                    provenance=provenance
                ))

        logger.info(f"Loaded {len(rules)} valid deletion rules from {rules_path.name}")
        return rules

    @classmethod
    def load_deletion_cases(cls, cases_path: Path) -> List[DeletionCase]:
        cls._check_file_exists(cases_path)
        cases: List[DeletionCase] = []
        seen_ids: Set[str] = set()

        with open(cases_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise MalformedRowError(f"Empty or corrupted CSV header in {cases_path}")
            SchemaValidator.validate_header("deletion_requests", reader.fieldnames, str(cases_path))

            for row_no, row in enumerate(reader, start=2):
                if not row or all(v is None or v.strip() == "" for v in row.values()):
                    continue
                SchemaValidator.validate_deletion_request_row(row, row_no, str(cases_path), seen_ids)

                case_id = row["case_id"].strip()
                provenance = SourceProvenance(
                    source_file=str(cases_path),
                    row_number=row_no,
                    entity_id=case_id,
                    captured_at=row["audit_at"].strip()
                )
                cases.append(DeletionCase(
                    case_id=case_id,
                    email=row["email"].strip(),
                    requested_at=row["requested_at"].strip(),
                    reported_status=row["reported_status"].strip(),
                    reported_at=row["reported_at"].strip(),
                    audit_at=row["audit_at"].strip(),
                    request_text=row["request_text"].strip(),
                    provenance=provenance
                ))

        logger.info(f"Loaded {len(cases)} valid deletion cases from {cases_path.name}")
        return cases

    @classmethod
    def load_user_identities(cls, identities_path: Path) -> List[Dict[str, str]]:
        cls._check_file_exists(identities_path)
        identities: List[Dict[str, str]] = []
        seen_ids: Set[str] = set()

        with open(identities_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise MalformedRowError(f"Empty or corrupted CSV header in {identities_path}")
            SchemaValidator.validate_header("user_identities", reader.fieldnames, str(identities_path))

            for row_no, row in enumerate(reader, start=2):
                if not row or all(v is None or v.strip() == "" for v in row.values()):
                    continue
                SchemaValidator.validate_user_identity_row(row, row_no, str(identities_path), seen_ids)

                clean_dict = {k.strip(): (v.strip() if v else "") for k, v in row.items()}
                clean_dict["_source_file"] = str(identities_path)
                clean_dict["_row_number"] = str(row_no)
                identities.append(clean_dict)

        logger.info(f"Loaded {len(identities)} user identities from {identities_path.name}")
        return identities

    @classmethod
    def load_user_audit_log(cls, audit_log_path: Path) -> List[Dict[str, str]]:
        cls._check_file_exists(audit_log_path)
        audit_records: List[Dict[str, str]] = []
        seen_ids: Set[str] = set()

        with open(audit_log_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise MalformedRowError(f"Empty or corrupted CSV header in {audit_log_path}")
            SchemaValidator.validate_header("user_audit_log", reader.fieldnames, str(audit_log_path))

            for row_no, row in enumerate(reader, start=2):
                if not row or all(v is None or v.strip() == "" for v in row.values()):
                    continue
                SchemaValidator.validate_user_audit_log_row(row, row_no, str(audit_log_path), seen_ids)

                clean_dict = {k.strip(): (v.strip() if v else "") for k, v in row.items()}
                clean_dict["_source_file"] = str(audit_log_path)
                clean_dict["_row_number"] = str(row_no)
                audit_records.append(clean_dict)

        logger.info(f"Loaded {len(audit_records)} audit log entries from {audit_log_path.name}")
        return audit_records

    @classmethod
    def load_system_activity(cls, activity_path: Path) -> List[Dict[str, str]]:
        cls._check_file_exists(activity_path)
        activities: List[Dict[str, str]] = []
        seen_ids: Set[str] = set()

        with open(activity_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise MalformedRowError(f"Empty or corrupted CSV header in {activity_path}")
            SchemaValidator.validate_header("system_activity", reader.fieldnames, str(activity_path))

            for row_no, row in enumerate(reader, start=2):
                if not row or all(v is None or v.strip() == "" for v in row.values()):
                    continue
                SchemaValidator.validate_system_activity_row(row, row_no, str(activity_path), seen_ids)

                clean_dict = {k.strip(): (v.strip() if v else "") for k, v in row.items()}
                clean_dict["_source_file"] = str(activity_path)
                clean_dict["_row_number"] = str(row_no)
                activities.append(clean_dict)

        logger.info(f"Loaded {len(activities)} system activity events from {activity_path.name}")
        return activities

    @classmethod
    def load_evidence_manifest(cls, manifest_path: Path) -> List[Dict[str, str]]:
        cls._check_file_exists(manifest_path)
        manifest: List[Dict[str, str]] = []
        seen_ids: Set[str] = set()

        with open(manifest_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise MalformedRowError(f"Empty or corrupted CSV header in {manifest_path}")
            SchemaValidator.validate_header("evidence_files", reader.fieldnames, str(manifest_path))

            for row_no, row in enumerate(reader, start=2):
                if not row or all(v is None or v.strip() == "" for v in row.values()):
                    continue
                SchemaValidator.validate_evidence_file_row(row, row_no, str(manifest_path), seen_ids)

                clean_dict = {k.strip(): (v.strip() if v else "") for k, v in row.items()}
                clean_dict["_source_file"] = str(manifest_path)
                clean_dict["_row_number"] = str(row_no)
                manifest.append(clean_dict)

        logger.info(f"Loaded {len(manifest)} evidence manifest records from {manifest_path.name}")
        return manifest
