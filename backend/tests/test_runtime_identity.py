from __future__ import annotations

import unittest

from app.runtime_identity import backend_runtime_identity
from app.version import GLACIAL_VERSION


class RuntimeIdentityTests(unittest.TestCase):
    def test_backend_identity_is_bounded_and_matches_authoritative_version(self) -> None:
        self.assertEqual(
            backend_runtime_identity(),
            {
                "schema_version": 1,
                "product_name": "Glacial",
                "product_version": GLACIAL_VERSION,
                "component": "owned-backend",
            },
        )


if __name__ == "__main__":
    unittest.main()

