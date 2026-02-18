from __future__ import annotations

import hashlib
import random
from typing import Any, Optional

import numpy as np


def _stable_hash(parts: list[str]) -> int:
    digest = hashlib.blake2b(digest_size=8)
    for part in parts:
        digest.update(part.encode("utf-8"))
        digest.update(b"|")
    return int.from_bytes(digest.digest(), "big", signed=False)


def derive_seed(base_seed: Optional[int], *tags: Any) -> int:
    """Derive a deterministic seed from a base seed and tag tuple."""
    seed_value = 0 if base_seed is None else int(base_seed)
    parts = [str(seed_value)] + [str(tag) for tag in tags]
    return _stable_hash(parts) % (2**32)


def make_random(base_seed: Optional[int], *tags: Any) -> random.Random:
    """Create a deterministic random.Random instance from seed + tags."""
    seed = derive_seed(base_seed, *tags)
    return random.Random(seed)


def make_numpy_rng(base_seed: Optional[int], *tags: Any) -> np.random.Generator:
    """Create a deterministic numpy RNG from seed + tags."""
    seed = derive_seed(base_seed, *tags)
    return np.random.default_rng(seed)
