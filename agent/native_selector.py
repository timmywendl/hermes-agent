"""Core/Profile-owned selector pins, independent of plugin load and gate config."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass

from agent.native_wire import canonical

POLICY_UNAVAILABLE = "Current project facts are UNKNOWN: POLICY_UNAVAILABLE."
_profiles = {}
_lock = threading.RLock()


class CandidateSelectorBundle:
    """Immutable accepted registry/selector/policy snapshot supplied by native Core."""

    __slots__ = ("_identity_check", "_raw", "digest")

    def __init__(self, record, expected_digest, *, identity_check=None):
        raw = canonical(record)
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            raise PermissionError("selector pin mismatch")
        required = {
            "profile",
            "revision",
            "registry_revision",
            "registry",
            "selector_revision",
            "plugin_id",
            "plugin_artifact_digest",
            "release_digest",
            "required_response_gates",
            "expires_at",
        }
        if (
            not isinstance(record, dict)
            or set(record) != required
            or not all(record.get(k) for k in required)
            or not isinstance(record["registry"], dict)
            or not isinstance(record["required_response_gates"], list)
            or not record["required_response_gates"]
            or len(record["plugin_artifact_digest"]) != 64
            or len(record["release_digest"]) != 64
        ):
            raise ValueError("invalid selector bundle")
        for item in record["registry"].values():
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("aliases"), list)
                or not item["aliases"]
                or not all(isinstance(x, str) and x.strip() for x in item["aliases"])
                or not item.get("repository")
            ):
                raise ValueError("invalid selector registry")
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "digest", expected_digest)
        object.__setattr__(self, "_identity_check", identity_check)

    def __setattr__(self, name, value):
        raise TypeError("immutable selector bundle")

    @property
    def record(self):
        return json.loads(self._raw)

    def matched_projects(self, message):
        if not isinstance(message, str):
            return ()
        text = " ".join(message.casefold().split())
        return tuple(
            key
            for key, item in self.record["registry"].items()
            if any(
                alias.casefold() in text
                for alias in (*item["aliases"], item["repository"])
            )
        )

    def classify(self, message):
        if not isinstance(message, str):
            return "CANDIDATE", False
        text = " ".join(message.casefold().split())
        aliases = [
            a.casefold()
            for item in self.record["registry"].values()
            for a in [*item["aliases"], item["repository"]]
        ]
        if not any(alias in text for alias in aliases):
            return "UNRELATED", False
        # Candidate remains protected even when quoting/reporting is not delegation.
        quoted = any(
            t in text
            for t in (
                "“",
                "”",
                "「",
                "」",
                "『",
                "』",
                '"',
                "'",
                "‘",
                "’",
                "引用",
                "举例",
                "例如",
                "解释这句话",
                "他说",
                "她说",
                "有人问",
                "不要",
                "别继续",
                "quote",
                "example",
                "he asked",
                "she asked",
                "they asked",
                "reported",
                "do not",
                "don't",
            )
        )
        actions = (
            "状态",
            "进展",
            "继续",
            "调查",
            "核验",
            "看看",
            "查询",
            "status",
            "progress",
            "continue",
            "check",
            "investigate",
        )
        return "CANDIDATE", not quoted and any(a in text for a in actions)

    def valid(self, policy):
        r = self.record
        if not callable(self._identity_check):
            return False
        try:
            actual = self._identity_check()
        except Exception:  # health: allow BLE001 -- identity provider failure closes project facts without leaking private paths
            return False
        if actual != {k: r[k] for k in ("plugin_artifact_digest", "release_digest")}:
            return False
        return (
            time.time() < r["expires_at"]
            and policy == r["required_response_gates"]
            and any(e.get("plugin_id") == r["plugin_id"] for e in policy)
        )


def install_selector(profile, bundle):
    """Called by Core bootstrap, never plugin registration or model arguments."""
    if (
        type(bundle) is not CandidateSelectorBundle
        or bundle.record["profile"] != profile
    ):
        raise PermissionError("native selector profile mismatch")
    with _lock:
        _profiles[profile] = bundle


def require_selector(profile):
    """Mark a project-capable native profile closed until its pins are available."""
    with _lock:
        _profiles[profile] = None


@dataclass(frozen=True)
class Selection:
    required: tuple
    bundle: object
    profile: str
    intake_allowed: bool
    digest: str
    candidate: bool
    projects: tuple = ()

    def valid(self):
        with _lock:
            if _profiles.get(self.profile) is not self.bundle:
                return False
        if self.bundle is None:
            return False
        try:
            from hermes_cli.config_effective import load_user_config_effective
            from hermes_constants import hermes_home_key

            if hermes_home_key() != self.profile:
                return False
            if not self.candidate:
                # Unrelatedness is proved by independent immutable selector pins,
                # even when the candidate-only mutable gate policy is unavailable.
                return self.bundle.valid(self.bundle.record["required_response_gates"])
            policy = (
                load_user_config_effective(fail_closed=True)
                .get("plugins", {})
                .get("required_response_gates")
            )
            return self.bundle.valid(policy)
        except (OSError, ValueError, TypeError, KeyError):
            return False


def select(profile, message):
    with _lock:
        if profile not in _profiles:
            return None
        bundle = _profiles[profile]
    if bundle is None:
        return Selection(("<policy-unavailable>",), None, profile, False, "", True)
    kind, intake = bundle.classify(message)
    if kind == "UNRELATED":
        return Selection((), bundle, profile, False, bundle.digest, False)
    return Selection(
        (bundle.record["plugin_id"],),
        bundle,
        profile,
        intake and len(bundle.matched_projects(message)) == 1,
        bundle.digest,
        True,
        bundle.matched_projects(message),
    )
