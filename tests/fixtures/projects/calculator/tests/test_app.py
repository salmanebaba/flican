import unittest

from app import calculate


class TestCalculator(unittest.TestCase):
    def test_adds_integers(self):
        self.assertEqual(calculate("2 + 3"), 5)

    def test_supports_negative_values(self):
        self.assertEqual(calculate("-2 + -3"), -5)

    def test_rejects_invalid_expressions(self):
        for expression in ("hello", "2 + three", "1 + 2 + 3"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                calculate(expression)


if __name__ == "__main__":
    unittest.main()
