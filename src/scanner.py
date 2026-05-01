"""
Core scanning engine — maps Copilot's blast radius across SharePoint and OneDrive.
Identifies over-permissive sharing links and stale access grants.
"""

import re
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional
from src.graph_client import GraphClient

RISK_CRITICAL = "critical"
RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"

BROAD_LINK_TYPES = {
    "organization": RISK_HIGH,
    "anonymous": RISK_CRITICAL,
    "everyone": RISK_CRITICAL,
}

SENSITIVE_FOLDER_PATTERNS = [
    r"salary|payroll|compensation|bonus",
    r"hr|human.?resource|personnel",
    r"legal|contract|nda|agreement",
    r"finance|budget|forecast|p&l|revenue",
    r"board|investor|fundrais",
    r"password|credential|secret|token|api.?key",
    r"health|medical|hipaa",
    r"audit|compliance|gdpr|sox",
]

STALE_DAYS_THRESHOLD = 180


@dataclass
class ExposureItem:
    item_id: str
    name: str
    web_url: str
    drive_id: str
    site_name: str
    risk_level: str
    risk_reasons: list[str] = field(default_factory=list)
    permission_type: str = ""
    granted_to: str = ""
    last_modified: Optional[str] = None
    created: Optional[str] = None
    size_bytes: int = 0
    is_folder: bool = False
    remediation: str = ""


@dataclass
class ScanResult:
    tenant_id: str
    scanned_at: str
    total_items_scanned: int = 0
    total_sites: int = 0
    total_users: int = 0
    critical_items: list[ExposureItem] = field(default_factory=list)
    high_items: list[ExposureItem] = field(default_factory=list)
    medium_items: list[ExposureItem] = field(default_factory=list)
    ai_readiness_score: int = 100
    score_breakdown: dict = field(default_factory=dict)
    users: list[dict] = field(default_factory=list)
    sites_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def all_exposures(self) -> list[ExposureItem]:
        return self.critical_items + self.high_items + self.medium_items

    @property
    def total_exposures(self) -> int:
        return len(self.all_exposures)

    @property
    def risk_grade(self) -> str:
        s = self.ai_readiness_score
        if s >= 85: return "A"
        if s >= 70: return "B"
        if s >= 55: return "C"
        if s >= 40: return "D"
        return "F"


def _is_sensitive_name(name: str) -> bool:
    n = name.lower()
    return any(re.search(p, n) for p in SENSITIVE_FOLDER_PATTERNS)


def _is_stale(date_str: Optional[str]) -> bool:
    if not date_str:
        return False
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days > STALE_DAYS_THRESHOLD
    except Exception:
        return False


def _remediation_for(risk_level: str, permission_type: str) -> str:
    if permission_type == "anonymous":
        return "Disable anonymous sharing link immediately. Set-SPOTenant -SharingCapability Disabled or revoke via SharePoint admin."
    if permission_type == "organization":
        return "Replace org-wide link with specific user/group permissions. Use 'Specific people' sharing in SharePoint."
    if risk_level == RISK_CRITICAL:
        return "Revoke permission and re-share only with required users. Review SharePoint admin > Active sites > Sharing."
    return "Review and restrict sharing to named users only."


def run_scan(client: GraphClient, progress_callback=None) -> ScanResult:
    def _progress(step, pct):
        if progress_callback:
            progress_callback(step, pct)

    me = client.get_me()
    result = ScanResult(
        tenant_id=me.get("id", "unknown"),
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

    _progress("Loading users…", 5)
    try:
        users = client.list_users()
        result.users = users
        result.total_users = len(users)
    except Exception as e:
        result.errors.append(f"Users: {e}")
        users = []

    _progress("Discovering SharePoint sites…", 20)
    try:
        sites = client.list_sites()
        result.total_sites = len(sites)
    except Exception as e:
        result.errors.append(f"Sites: {e}")
        sites = []

    total_sites = len(sites)
    for idx, site in enumerate(sites):
        site_id = site.get("id", "")
        site_name = site.get("displayName") or site.get("name", "Unknown")
        result.sites_scanned.append(site_name)
        pct = 20 + int((idx / max(total_sites, 1)) * 60)
        _progress(f"Scanning {site_name}…", pct)

        try:
            drives = client.list_drives(site_id)
        except Exception as e:
            result.errors.append(f"Drives for {site_name}: {e}")
            continue

        for drive in drives:
            drive_id = drive.get("id", "")
            try:
                items = client.list_drive_items(drive_id)
            except Exception as e:
                result.errors.append(f"Items in {site_name}/{drive_id}: {e}")
                continue

            for item in items:
                result.total_items_scanned += 1
                item_id = item.get("id", "")
                item_name = item.get("name", "")
                is_folder = "folder" in item
                shared = item.get("shared")

                if not shared:
                    continue

                try:
                    perms = client.get_item_permissions(drive_id, item_id)
                except Exception:
                    continue

                for perm in perms:
                    link = perm.get("link", {})
                    link_scope = link.get("scope", "")
                    granted_to_many = perm.get("grantedToIdentitiesV2", [])
                    granted_to = perm.get("grantedTo", {})
                    created_dt = perm.get("createdDateTime")
                    is_stale = _is_stale(created_dt)
                    is_sensitive = _is_sensitive_name(item_name)

                    risk_reasons = []
                    risk_level = RISK_LOW
                    permission_label = link_scope or "direct"

                    if link_scope == "anonymous":
                        risk_level = RISK_CRITICAL
                        risk_reasons.append("Anonymous link — anyone with URL can access")
                    elif link_scope == "organization":
                        risk_level = RISK_HIGH
                        risk_reasons.append("Org-wide link — all internal users + Copilot can read")
                        if is_sensitive:
                            risk_level = RISK_CRITICAL
                            risk_reasons.append(f"Sensitive folder name: {item_name}")
                    elif is_sensitive and is_stale:
                        risk_level = RISK_HIGH
                        risk_reasons.append("Sensitive folder with stale permissions (>180 days)")
                    elif is_sensitive:
                        risk_level = RISK_MEDIUM
                        risk_reasons.append(f"Sensitive folder pattern matched: {item_name}")
                    elif is_stale:
                        risk_level = RISK_MEDIUM
                        risk_reasons.append("Stale permissions — last granted >180 days ago")

                    if risk_level == RISK_LOW:
                        continue

                    if granted_to:
                        user_info = granted_to.get("user", {})
                        gt_label = user_info.get("displayName") or user_info.get("email", "Unknown user")
                    elif granted_to_many:
                        gt_label = f"{len(granted_to_many)} identities"
                    else:
                        gt_label = link_scope or "Broad access"

                    exposure = ExposureItem(
                        item_id=item_id,
                        name=item_name,
                        web_url=item.get("webUrl", ""),
                        drive_id=drive_id,
                        site_name=site_name,
                        risk_level=risk_level,
                        risk_reasons=risk_reasons,
                        permission_type=permission_label,
                        granted_to=gt_label,
                        last_modified=item.get("lastModifiedDateTime"),
                        created=created_dt,
                        size_bytes=item.get("size", 0),
                        is_folder=is_folder,
                        remediation=_remediation_for(risk_level, permission_label),
                    )

                    if risk_level == RISK_CRITICAL:
                        result.critical_items.append(exposure)
                    elif risk_level == RISK_HIGH:
                        result.high_items.append(exposure)
                    else:
                        result.medium_items.append(exposure)

    _progress("Calculating AI Readiness Score…", 90)
    result.ai_readiness_score, result.score_breakdown = _calculate_score(result)
    _progress("Complete", 100)
    return result


def _calculate_score(result: ScanResult) -> tuple[int, dict]:
    score = 100
    breakdown = {}

    crit_penalty = min(len(result.critical_items) * 8, 40)
    score -= crit_penalty
    breakdown["Critical exposures"] = f"-{crit_penalty} ({len(result.critical_items)} items)"

    high_penalty = min(len(result.high_items) * 4, 25)
    score -= high_penalty
    breakdown["High exposures"] = f"-{high_penalty} ({len(result.high_items)} items)"

    med_penalty = min(len(result.medium_items), 15)
    score -= med_penalty
    breakdown["Medium exposures"] = f"-{med_penalty} ({len(result.medium_items)} items)"

    err_penalty = min(len(result.errors) * 2, 10)
    score -= err_penalty
    breakdown["Scan errors"] = f"-{err_penalty} ({len(result.errors)} errors)"

    return max(score, 0), breakdown
