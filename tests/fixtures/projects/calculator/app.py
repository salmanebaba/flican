"""A small calculator used as a local flican scan target."""

import argparse


def calculate(expression: str) -> int:
    left, right = expression.split("+")
    return int(left) + int(right)


def main() -> None:
    parser = argparse.ArgumentParser(description="Add two integers.")
    parser.add_argument("expression", help='An addition, for example "2 + 3".')
    args = parser.parse_args()

    try:
        result = calculate(args.expression)
    except ValueError:
        parser.error('Expected two integers separated by "+", for example "2 + 3".')

    print(result)


if __name__ == "__main__":
    main()
