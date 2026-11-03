"""Regression test for the vendored idna (CVE-2024-3651, GHSA-jjg7-2v4v-x38h)."""

from typing import Any, Dict

import pytest

from pip._vendor import idna
from pip._vendor.idna import core, idnadata


class _CountingTypes(Dict[int, Any]):
    lookups = 0

    def get(self, key: int, default: Any = None) -> Any:
        type(self).lookups += 1
        return super().get(key, default)


def test_vendored_idna_is_fixed_release() -> None:
    assert tuple(int(x) for x in idna.__version__.split(".")[:2]) >= (3, 7)


def test_contextj_scan_is_linear(monkeypatch: pytest.MonkeyPatch) -> None:
    # A dual-joining letter, a run of non-joining letters, many ZWNJs, more
    # non-joining letters and another dual-joining letter. Before idna 3.7 each
    # ZWNJ scanned past the whole run on both sides, so the CONTEXTJ check made
    # O(n**2) joining-type lookups and encode() took seconds for n in the
    # low thousands.
    counting = _CountingTypes(idnadata.joining_types)
    _CountingTypes.lookups = 0
    monkeypatch.setattr(idnadata, "joining_types", counting)

    n = 300
    label = "ب" + "a" * n + "‌" * n + "a" * n + "ب"
    with pytest.raises(idna.IDNAError):
        core.encode(label)

    # Linear behaviour stops at the first non-transparent neighbour: a handful
    # of lookups per joiner. The unfixed scan needs about 3 * n**2 (270,000).
    assert _CountingTypes.lookups < 20 * n
