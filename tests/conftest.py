"""Shared fixtures. Configures a product so builders have an identity to stamp."""

from __future__ import annotations

from collections.abc import Callable

import pytest

import ocsf_emitter

# A fixed epoch-ms timestamp used across tests for stable output.
FIXED_TIME_MS = 1_752_566_400_000


@pytest.fixture(autouse=True)
def _configured_product() -> None:
    """Set a deterministic product for every test."""
    ocsf_emitter.configure_product(
        name="Test Detector", vendor_name="Example, Inc.", version="1.0.0"
    )


@pytest.fixture
def fixed_clock() -> Callable[[], int]:
    """A clock returning a fixed epoch-ms timestamp."""
    return lambda: FIXED_TIME_MS
