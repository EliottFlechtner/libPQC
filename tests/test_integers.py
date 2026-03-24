import unittest
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.integers import SymmetricModulo, IntegersRing


class TestIntegersRing(unittest.TestCase):
    """Test cases for IntegersRing class."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z5 = IntegersRing(5)
        self.Z7 = IntegersRing(7)
        self.Z2 = IntegersRing(2)

    def test_init(self):
        """Test IntegersRing initialization."""
        self.assertEqual(self.Z5.modulus, 5)
        self.assertEqual(self.Z7.modulus, 7)

    def test_add(self):
        """Test addition in the ring."""
        self.assertEqual(self.Z5.add(2, 3), 0)  # 2+3=5≡0 (mod 5)
        self.assertEqual(self.Z5.add(4, 4), 3)  # 4+4=8≡3 (mod 5)
        self.assertEqual(self.Z5.add(0, 0), 0)
        self.assertEqual(self.Z7.add(6, 2), 1)  # 6+2=8≡1 (mod 7)

    def test_sub(self):
        """Test subtraction in the ring."""
        self.assertEqual(self.Z5.sub(2, 3), 4)  # 2-3=-1≡4 (mod 5)
        self.assertEqual(self.Z5.sub(0, 1), 4)  # 0-1=-1≡4 (mod 5)
        self.assertEqual(self.Z5.sub(5, 0), 0)
        self.assertEqual(self.Z7.sub(1, 3), 5)  # 1-3=-2≡5 (mod 7)

    def test_mul(self):
        """Test multiplication in the ring."""
        self.assertEqual(self.Z5.mul(2, 3), 1)  # 2*3=6≡1 (mod 5)
        self.assertEqual(self.Z5.mul(4, 4), 1)  # 4*4=16≡1 (mod 5)
        self.assertEqual(self.Z5.mul(0, 5), 0)
        self.assertEqual(self.Z7.mul(3, 4), 5)  # 3*4=12≡5 (mod 7)

    def test_neg(self):
        """Test negation in the ring."""
        self.assertEqual(self.Z5.neg(0), 0)
        self.assertEqual(self.Z5.neg(1), 4)  # -1≡4 (mod 5)
        self.assertEqual(self.Z5.neg(3), 2)  # -3≡2 (mod 5)
        self.assertEqual(self.Z7.neg(2), 5)  # -2≡5 (mod 7)

    def test_inf_norm_basic(self):
        """Test infinity norm with basic values."""
        self.assertEqual(self.Z5.inf_norm(0), 0)
        self.assertEqual(self.Z5.inf_norm(1), 1)
        self.assertEqual(self.Z5.inf_norm(2), 2)
        self.assertEqual(self.Z7.inf_norm(3), 3)

    def test_inf_norm_symmetric_conversion(self):
        """Test infinity norm using symmetric representatives."""
        Z137 = IntegersRing(137)
        # In Z_137, symmetric range is [-68, 68]
        self.assertEqual(Z137.inf_norm(135), 2)  # 135 ≡ -2 (mod 137)
        self.assertEqual(Z137.inf_norm(136), 1)  # 136 ≡ -1 (mod 137)
        self.assertEqual(Z137.inf_norm(68), 68)  # 68 is maximum symmetric
        self.assertEqual(Z137.inf_norm(69), 68)  # 69 ≡ -68 (mod 137)
        self.assertEqual(Z137.inf_norm(70), 67)  # 70 ≡ -67 (mod 137)

    def test_inf_norm_even_modulus(self):
        """Test infinity norm with even modulus."""
        Z128 = IntegersRing(128)
        # In Z_128, symmetric range is [-64, 63]
        self.assertEqual(Z128.inf_norm(127), 1)  # 127 ≡ -1 (mod 128)
        self.assertEqual(Z128.inf_norm(64), 64)  # 64 at boundary
        self.assertEqual(Z128.inf_norm(65), 63)  # 65 ≡ -63 (mod 128)

    def test_inf_norm_all_positive(self):
        """Test that inf_norm is always non-negative."""
        for val in range(137):
            norm = IntegersRing(137).inf_norm(val)
            self.assertGreaterEqual(norm, 0)


class TestSymmetricModulo(unittest.TestCase):
    """Test cases for SymmetricModulo class."""

    def test_symmetric_odd_modulus(self):
        """Test symmetric representative with odd modulus."""
        sym = SymmetricModulo(5)
        self.assertEqual(sym.symmetric(0), 0)
        self.assertEqual(sym.symmetric(1), 1)
        self.assertEqual(sym.symmetric(2), 2)
        self.assertEqual(sym.symmetric(3), -2)  # 3 > 2, so 3 - 5 = -2
        self.assertEqual(sym.symmetric(4), -1)  # 4 > 2, so 4 - 5 = -1
        self.assertEqual(sym.symmetric(5), 0)  # 5 ≡ 0 (mod 5)

    def test_symmetric_odd_modulus_137(self):
        """Test symmetric representative for Z_137 (odd)."""
        sym = SymmetricModulo(137)
        self.assertEqual(sym.symmetric(68), 68)  # At boundary
        self.assertEqual(sym.symmetric(69), -68)  # 69 > 68, so 69 - 137 = -68
        self.assertEqual(sym.symmetric(135), -2)  # 135 > 68, so 135 - 137 = -2
        self.assertEqual(sym.symmetric(136), -1)  # 136 > 68, so 136 - 137 = -1

    def test_symmetric_even_modulus(self):
        """Test symmetric representative with even modulus."""
        sym = SymmetricModulo(128)
        self.assertEqual(sym.symmetric(0), 0)
        self.assertEqual(sym.symmetric(63), 63)  # 63 < 64, stays positive
        self.assertEqual(
            sym.symmetric(64), -64
        )  # For even, 64 >= 64, so 64 - 128 = -64
        self.assertEqual(sym.symmetric(65), -63)  # 65 >= 64, so 65 - 128 = -63
        self.assertEqual(sym.symmetric(127), -1)  # 127 >= 64, so 127 - 128 = -1

    def test_symmetric_negative_input(self):
        """Test symmetric representative with negative input (should work via modulo)."""
        sym = SymmetricModulo(5)
        self.assertEqual(
            sym.symmetric(-1), -1
        )  # -1 ≡ 4 (mod 5), then 4 > 2 so 4-5 = -1
        self.assertEqual(
            sym.symmetric(-2), -2
        )  # -2 ≡ 3 (mod 5), then 3 > 2 so 3-5 = -2
        self.assertEqual(sym.symmetric(-3), 2)  # -3 ≡ 2 (mod 5), then 2 <= 2 so stays 2

    def test_symmetric_large_input(self):
        """Test symmetric representative with values > modulus."""
        sym = SymmetricModulo(5)
        self.assertEqual(sym.symmetric(10), 0)  # 10 ≡ 0 (mod 5), stays 0
        self.assertEqual(sym.symmetric(12), 2)  # 12 ≡ 2 (mod 5), 2 <= 2 so stays 2
        self.assertEqual(sym.symmetric(137), 2)  # 137 ≡ 2 (mod 5), 2 <= 2 so stays 2


if __name__ == "__main__":
    unittest.main()
