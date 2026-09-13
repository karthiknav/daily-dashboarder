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
class CheckmarxConfig:
    task_name: str
    min_severity: str


@dataclass
class ScanTarget:
    project: str
    repo: str
    pipeline: str
    checkout_url: str
    target_branch: str
    features: List[str]


@dataclass
class GraphConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    mailbox: str
    lookback_hours: int
    folder: str = "inbox"


def load_ado_config() -> AdoConfig:
    org_url = os.environ.get("ADO_ORG_URL", "")
    pat = os.environ.get("ADO_PAT") or os.environ.get("AZDO_PAT", "")
    project = os.environ.get("ADO_PROJECT", "")
    if not org_url or not pat:
        raise ValueError("ADO_ORG_URL and ADO_PAT (or AZDO_PAT) must be set")
    return AdoConfig(org_url=org_url, project=project, pat=pat)


def load_checkmarx_config() -> CheckmarxConfig:
    return CheckmarxConfig(
        task_name=os.environ.get("CHECKMARX_TASK_NAME", "RabobankCheckmarx"),
        min_severity=os.environ.get("CHECKMARX_MIN_SEVERITY", "medium"),
    )


def load_graph_config() -> Optional[GraphConfig]:
    """Announcements are an optional feature: return None (rather than raising)
    when Microsoft Graph credentials aren't configured, so the scan still runs
    for deployments that haven't set up a mailbox yet."""
    tenant_id = os.environ.get("MS_GRAPH_TENANT_ID", "")
    client_id = os.environ.get("MS_GRAPH_CLIENT_ID", "")
    client_secret = os.environ.get("MS_GRAPH_CLIENT_SECRET", "")
    mailbox = os.environ.get("MS_GRAPH_MAILBOX", "")
    if not (tenant_id and client_id and client_secret and mailbox):
        return None
    return GraphConfig(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        mailbox=mailbox,
        lookback_hours=int(os.environ.get("ANNOUNCEMENTS_LOOKBACK_HOURS", "24")),
        folder=os.environ.get("MS_GRAPH_MAIL_FOLDER", "inbox"),
    )


def load_targets(config_path: Path) -> List[ScanTarget]:
    data: Dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    targets: List[ScanTarget] = []
    for item in data.get("targets") or []:
        targets.append(
            ScanTarget(
                project=str(item.get("project", "")).strip(),
                repo=str(item.get("repo", "")).strip(),
                pipeline=str(item.get("pipeline", "")).strip(),
                checkout_url=str(item.get("checkout_url", "")).strip(),
                target_branch=str(item.get("target_branch", "main")).strip() or "main",
                features=item.get("features") or [],
            )
        )
    return targets
