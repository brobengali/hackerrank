"""Configuration settings for Ghost Data Still Exists deletion audit agent.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from code.core.errors import MissingFileError

@dataclass
class Config:
    repo_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    dataset_dir: Optional[Path] = None
    evidence_dir: Path = field(init=False)
    deletion_rules_path: Path = field(init=False)
    user_identities_path: Path = field(init=False)
    user_audit_log_path: Path = field(init=False)
    system_activity_path: Path = field(init=False)
    evidence_files_path: Path = field(init=False)
    deletion_requests_path: Path = field(init=False)
    sample_requests_path: Path = field(init=False)
    sample_output_path: Path = field(init=False)
    output_path: Path = field(init=False)
    
    # Execution options
    enable_ai: bool = False
    ai_provider: str = "none"  # "gemini", "openai", or "none"
    read_only: bool = True
    strict_validation: bool = True

    def __post_init__(self) -> None:
        if not self.dataset_dir:
            self.dataset_dir = self.repo_root / "dataset"
        self.evidence_dir = self.dataset_dir / "evidence"
        self.deletion_rules_path = self.dataset_dir / "deletion_rules.csv"
        self.user_identities_path = self.dataset_dir / "user_identities.csv"
        self.user_audit_log_path = self.dataset_dir / "user_audit_log.csv"
        self.system_activity_path = self.dataset_dir / "system_activity.csv"
        self.evidence_files_path = self.dataset_dir / "evidence_files.csv"
        self.deletion_requests_path = self.dataset_dir / "deletion_requests.csv"
        self.sample_requests_path = self.dataset_dir / "sample_deletion_requests.csv"
        self.sample_output_path = self.dataset_dir / "sample_output.csv"
        self.output_path = self.repo_root / "output.csv"

    def validate_paths(self, require_production_inputs: bool = False) -> None:
        """Verifies that mandatory dataset files exist on disk."""
        mandatory: List[Path] = [
            self.deletion_rules_path,
            self.user_identities_path,
            self.user_audit_log_path,
            self.system_activity_path,
            self.evidence_files_path,
        ]
        if require_production_inputs:
            mandatory.append(self.deletion_requests_path)

        missing = [p for p in mandatory if not p.exists()]
        if missing:
            raise MissingFileError(
                f"Missing required dataset files: {[str(p) for p in missing]}",
                {"missing_files": [str(p) for p in missing]}
            )
