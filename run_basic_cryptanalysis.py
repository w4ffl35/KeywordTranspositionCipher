#!/usr/bin/env python3
"""
Command-line interface for Basic Cryptanalysis.

Decrypts monoalphabetic substitution ciphers using pattern matching and search.
"""

import sys
from basiccryptanalysis.basic_cryptanalysis import BasicCryptanalysis


def parse_piped_input() -> str:
    """Parse piped input from stdin.

    Returns:
        Ciphertext string
    """
    data = sys.stdin.read().strip()
    return data


def interactive_input() -> str:
    """Prompt user for interactive ciphertext input.

    Returns:
        Ciphertext string from user input
    """
    print("Interactive mode: enter a single line of ciphertext (space-separated words)")
    return input("Ciphertext: ")


if __name__ == "__main__":
    if sys.stdin.isatty():
        secrets = interactive_input()
    else:
        secrets = parse_piped_input()

    if not secrets:
        print("No input detected; see README.md for usage examples.")
        sys.exit(1)
    bc = BasicCryptanalysis(secrets=secrets)
    bc.execute()
