"""VirusTotal file reputation scanning service."""
from __future__ import annotations

import hashlib
import logging

import httpx

from ..core.config import get_settings

log = logging.getLogger("bastion.virustotal")


class VTScanner:
    def __init__(self) -> None:
        settings = get_settings()
        self._api_key = settings.vt_api_key
        self._base = settings.vt_base_url
        self._enabled = bool(self._api_key)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    async def check_hash(self, sha256: str) -> dict:
        """Query VT for a file hash. Returns structured result."""
        if not self._enabled:
            return {"status": "disabled", "sha256": sha256}

        url = f"{self._base}/files/{sha256}"
        headers = {"x-apikey": self._api_key}

        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 404:
                    return {"status": "unknown", "sha256": sha256, "message": "Not found in VT database"}
                if resp.status_code == 429:
                    log.warning("VT rate limit hit")
                    return {"status": "error", "sha256": sha256, "message": "Rate limited"}
                resp.raise_for_status()
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                link = f"https://www.virustotal.com/gui/file/{sha256}"

                if malicious > 0:
                    status = "malicious"
                elif suspicious > 0:
                    status = "suspicious"
                else:
                    status = "clean"

                return {
                    "status": status,
                    "sha256": sha256,
                    "detection_count": malicious + suspicious,
                    "total_engines": total,
                    "link": link,
                    "meaningful_name": attrs.get("meaningful_name", ""),
                    "stats": stats,
                }
            except httpx.HTTPStatusError as e:
                log.error("VT API error: %s", e)
                return {"status": "error", "sha256": sha256, "message": str(e)}
            except Exception as e:
                log.error("VT request failed: %s", e)
                return {"status": "error", "sha256": sha256, "message": str(e)}

    async def scan_file_bytes(self, data: bytes, filename: str = "unknown") -> dict:
        sha = self.sha256_bytes(data)
        result = await self.check_hash(sha)
        result["file_name"] = filename
        result["file_size"] = len(data)
        return result
