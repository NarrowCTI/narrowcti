"""Provider-neutral detection artifact representation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

from ._normalization import normalize_refs, optional_text, required_text


_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _optional_content(value):
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("content must be a non-empty string or None")
    return value


@dataclass(frozen=True)
class DetectionArtifact:
    id: str
    requirement_id: str
    format: str
    source_ref: str | None = None
    content: str | None = None
    content_ref: str | None = None
    backend: str | None = None
    version: str = "1"
    provenance: tuple[str, ...] = ()
    content_sha256: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "id", required_text(self.id, "id"))
        object.__setattr__(self, "requirement_id", required_text(self.requirement_id, "requirement_id"))
        object.__setattr__(self, "format", required_text(self.format, "format").lower())
        object.__setattr__(self, "source_ref", optional_text(self.source_ref, "source_ref"))
        object.__setattr__(self, "content", _optional_content(self.content))
        object.__setattr__(self, "content_ref", optional_text(self.content_ref, "content_ref"))
        object.__setattr__(self, "backend", optional_text(self.backend, "backend"))
        object.__setattr__(self, "version", required_text(self.version, "version"))
        object.__setattr__(self, "provenance", normalize_refs(self.provenance, "provenance"))
        if self.content is None and self.content_ref is None:
            raise ValueError("content or content_ref is required")
        if self.content_sha256 is not None:
            digest = required_text(self.content_sha256, "content_sha256")
            if not _SHA256_PATTERN.fullmatch(digest):
                raise ValueError("content_sha256 must be 64 hexadecimal characters")
            object.__setattr__(self, "content_sha256", digest.lower())

    def to_dict(self):
        return {
            "id": self.id,
            "requirement_id": self.requirement_id,
            "format": self.format,
            "source_ref": self.source_ref,
            "content": self.content,
            "content_ref": self.content_ref,
            "backend": self.backend,
            "version": self.version,
            "provenance": list(self.provenance),
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("detection artifact must be a mapping")
        return cls(
            id=value.get("id"),
            requirement_id=value.get("requirement_id"),
            format=value.get("format"),
            source_ref=value.get("source_ref"),
            content=value.get("content"),
            content_ref=value.get("content_ref"),
            backend=value.get("backend"),
            version=value.get("version", "1"),
            provenance=value.get("provenance") or (),
            content_sha256=value.get("content_sha256"),
        )


__all__ = ["DetectionArtifact"]
