"""Env + target-list configuration, mirroring yapl-upgrader's .env/python-dotenv
convention (see core/llm.py, migrate_pipeline.py) plus a pipelines.yml listing
the repos/pipelines to scan (yapl-upgrader only ever targets one fixed repo
via .env, but daily-dashboard scans many)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()


@dataclass
class AdoConfig:
    org_url: str
    project: str
    pat: str


@dataclass
class ScanTarget:
    project: str
    repo: str
    pipeline: str
    checkout_url: str
    target_branch: str
    features: List[str]


def load_ado_config() -> AdoConfig:
    org_url = os.environ.get("ADO_ORG_URL", "")
    pat = os.environ.get("ADO_PAT") or os.environ.get("AZDO_PAT", "")
    project = os.environ.get("ADO_PROJECT", "")
    if not org_url or not pat:
        raise ValueError("ADO_ORG_URL and ADO_PAT (or AZDO_PAT) must be set")
    return AdoConfig(org_url=org_url, project=project, pat=pat)


def load_targets(config_path: Path) -> List[ScanTarget]:
    data: Dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    targets: List[ScanTarget] = []
    for item in data.get("targets") or []:
        targets.append(
            ScanTarget(
                project=item.get("project", ""),
                repo=item.get("repo", ""),
                pipeline=item.get("pipeline", ""),
                checkout_url=item.get("checkout_url", ""),
                target_branch=item.get("target_branch", "main"),
                features=item.get("features") or [],
            )
        )
    return targets
