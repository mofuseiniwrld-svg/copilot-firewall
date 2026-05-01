"""
Microsoft Graph API client — read-only, least-privilege.
All calls use delegated permissions scoped to user consent.
"""

import requests
from typing import Iterator, Optional
from dataclasses import dataclass, field

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


@dataclass
class GraphClient:
    access_token: str

    @property
    def headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "ConsistencyLevel": "eventual",
        }

    def get(self, url: str, params: dict = None) -> dict:
        resp = requests.get(url, headers=self.headers, params=params or {}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def paginate(self, url: str, params: dict = None) -> Iterator[dict]:
        """Auto-paginate Graph API responses."""
        next_url = url
        while next_url:
            data = self.get(next_url, params if next_url == url else None)
            yield from data.get("value", [])
            next_url = data.get("@odata.nextLink")

    def list_users(self) -> list[dict]:
        url = f"{GRAPH_BASE}/users"
        params = {"$select": "id,displayName,mail,userPrincipalName,assignedLicenses", "$top": "999"}
        return list(self.paginate(url, params))

    def get_me(self) -> dict:
        return self.get(f"{GRAPH_BASE}/me")

    def list_sites(self) -> list[dict]:
        url = f"{GRAPH_BASE}/sites"
        params = {"search": "*", "$select": "id,name,displayName,webUrl", "$top": "200"}
        return list(self.paginate(url, params))

    def list_drives(self, site_id: str) -> list[dict]:
        url = f"{GRAPH_BASE}/sites/{site_id}/drives"
        return list(self.paginate(url))

    def list_drive_items(self, drive_id: str, folder_id: str = "root") -> list[dict]:
        url = f"{GRAPH_BASE}/drives/{drive_id}/items/{folder_id}/children"
        params = {"$select": "id,name,size,webUrl,createdDateTime,lastModifiedDateTime,folder,file,shared", "$top": "200"}
        return list(self.paginate(url, params))

    def get_item_permissions(self, drive_id: str, item_id: str) -> list[dict]:
        url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}/permissions"
        return list(self.paginate(url))

    def list_user_drives(self, user_id: str) -> list[dict]:
        url = f"{GRAPH_BASE}/users/{user_id}/drives"
        return list(self.paginate(url))

    def list_shared_items(self) -> list[dict]:
        url = f"{GRAPH_BASE}/me/drive/sharedWithMe"
        return list(self.paginate(url))

    def list_groups(self) -> list[dict]:
        url = f"{GRAPH_BASE}/groups"
        params = {"$select": "id,displayName,mail,groupTypes", "$top": "999"}
        return list(self.paginate(url, params))

    def list_sensitivity_labels(self) -> list[dict]:
        try:
            url = f"{GRAPH_BETA}/security/informationProtection/sensitivityLabels"
            return list(self.paginate(url))
        except Exception:
            return []
