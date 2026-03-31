import unittest

from src.schemes.utils import (
    derive_deterministic_rng,
    derive_deterministic_rngs,
    inner_product_entries,
    mat_vec_add,
    resolve_named_params,
    to_seed_bytes,
)


class TestSchemeUtils(unittest.TestCase):
    def test_to_seed_bytes_validation(self):
        self.assertEqual(to_seed_bytes("abc"), b"abc")
        self.assertEqual(to_seed_bytes(b"abc"), b"abc")
        with self.assertRaises(TypeError):
            _ = to_seed_bytes(1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = to_seed_bytes("")

    def test_resolve_named_params_merge_and_missing(self):
        presets = {"X": {"name": "X", "a": 1, "b": 2}}

        self.assertEqual(
            resolve_named_params(
                params="X",
                preset_map=presets,
                required=("a",),
                unknown_message="bad",
                type_message="bad type",
            )["a"],
            1,
        )

        merged = resolve_named_params(
            params={"name": "X", "b": 9},
            preset_map=presets,
            required=("a", "b"),
            unknown_message="bad",
            type_message="bad type",
        )
        self.assertEqual(merged["a"], 1)
        self.assertEqual(merged["b"], 9)

        with self.assertRaises(ValueError):
            _ = resolve_named_params(
                params={"a": 1},
                preset_map=presets,
                required=("a", "b"),
                unknown_message="bad",
                type_message="bad type",
                missing_message_prefix="missing keys",
            )

    def test_deterministic_rng_helpers(self):
        rng1 = derive_deterministic_rng(b"seed", "label")
        rng2 = derive_deterministic_rng(b"seed", "label")
        self.assertEqual(rng1.randrange(10**6), rng2.randrange(10**6))

        a1, b1 = derive_deterministic_rngs(b"seed", ("a", "b"))
        a2, b2 = derive_deterministic_rngs(b"seed", ("a", "b"))
        self.assertEqual(a1.randrange(10**6), a2.randrange(10**6))
        self.assertEqual(b1.randrange(10**6), b2.randrange(10**6))

    def test_mat_vec_add(self):
        matrix = [[1, 2], [3, 4]]
        vector = [10, 20]
        add = [7, 8]
        result = mat_vec_add(matrix, vector, add, 0)
        self.assertEqual(result, [57, 118])

        with self.assertRaises(ValueError):
            _ = mat_vec_add([[1]], [2, 3], [4], 0)

    def test_inner_product_entries(self):
        self.assertEqual(inner_product_entries([1, 2], [3, 4], 0), 11)

        with self.assertRaises(TypeError):
            _ = inner_product_entries("bad", [1], 0)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _ = inner_product_entries([1], "bad", 0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = inner_product_entries([1], [1, 2], 0)


if __name__ == "__main__":
    unittest.main()
