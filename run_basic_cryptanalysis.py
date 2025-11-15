#!/usr/bin/env python3
import sys
from basiccryptanalysis.basic_cryptanalysis import BasicCryptanalysis


def parse_piped_input():
    data = sys.stdin.read().strip()
    return data


def interactive_input():
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
