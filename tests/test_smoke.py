"""Smoke tests — ensure package imports and version is set."""

import iil_codeguard


def test_should_export_version():
    assert iil_codeguard.__version__
    assert iil_codeguard.__version__.startswith("2026.")
