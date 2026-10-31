"""Context and uncertainty policies for AIT alert ranking."""

from __future__ import annotations

import pandas as pd


def apply_asset_context(alerts: pd.DataFrame, mode: str = "flat") -> pd.DataFrame:
    """Attach an asset criticality factor.

    The `asset_profile` mode is a deterministic, detector-label-free policy based
    on host/IP/native metadata. It is intentionally simple and auditable; it is
    not learned from attack labels.
    """

    out = alerts.copy()
    if mode == "flat":
        out["asset_criticality"] = 1.0
        return out
    if mode != "asset_profile":
        raise ValueError(f"Unsupported context mode: {mode}")

    out["asset_criticality"] = [
        _asset_factor(host, ip, native_key, native_category)
        for host, ip, native_key, native_category in zip(
            out.get("host", ""),
            out.get("ip", ""),
            out.get("native_key", ""),
            out.get("native_category", ""),
        )
    ]
    return out


def apply_uncertainty_policy(alerts: pd.DataFrame, mode: str = "table") -> pd.DataFrame:
    """Adjust uncertainty factors for ranking."""

    out = alerts.copy()
    if mode == "table":
        return out
    if mode != "ambiguity_aware":
        raise ValueError(f"Unsupported uncertainty mode: {mode}")

    phase = out["attack_phase"].fillna("unknown")
    precision = out.get("mapped_precision", 0.0)
    purity = out.get("mapped_phase_purity", 0.0)
    precision = pd.Series(precision, index=out.index).fillna(0.0).astype(float)
    purity = pd.Series(purity, index=out.index).fillna(0.0).astype(float)
    base = out["uncertainty_factor"].fillna(0.5).astype(float)

    ambiguity_penalty = 0.20 * (1.0 - precision) + 0.15 * (1.0 - purity)
    adjusted = (base + ambiguity_penalty).clip(lower=0.0, upper=0.5)
    adjusted[phase == "unknown"] = 0.5
    out["uncertainty_factor"] = adjusted
    return out


def _asset_factor(host: object, ip: object, native_key: object, native_category: object) -> float:
    text = " ".join(
        str(value or "").lower()
        for value in [host, ip, native_key, native_category]
    )
    if any(token in text for token in ["firewall", "gateway", "dns", "domain", "192.168.255.254"]):
        return 1.0
    if any(token in text for token in ["intranet", "apache", "web", "horde", "wordpress", "proxy"]):
        return 0.9
    if "mail" in text or "dovecot" in text or "postfix" in text or "smtp" in text:
        return 0.85
    if "share" in text or "cloud" in text or "files" in text:
        return 0.8
    if "wazuh-client" in text:
        return 0.65
    if text.strip():
        return 0.6
    return 0.5
