#!/usr/bin/env python3
import sys
import argparse
from keywordtranspositioncipher.keyword_transposition_cipher import (
    KeywordTranspositionCipher,
)


def parse_piped_input():
    """Parse piped input expected in the CLI format:
    n\nkey1\nsecret1\nkey2\nsecret2\n..."""
    data = sys.stdin.read().splitlines()
    data = [l for l in data if l and l.strip()]
    if not data:
        return []
    try:
        n = int(data[0].strip())
    except ValueError:
        # If first line isn't an int, try treating the input as a single pair
        if len(data) >= 2:
            return [(data[0].strip(), data[1].split())]
        return []
    pairs = []
    # Safe-guard: ensure enough lines are available
    available_pairs_lines = data[1 : 1 + 2 * n]
    for i in range(0, len(available_pairs_lines), 2):
        key = "".join(
            [c for c in available_pairs_lines[i].strip().upper() if c.isalpha()]
        )
        try:
            secret = [
                "".join([c for c in w.upper() if c.isalpha()])
                for w in available_pairs_lines[i + 1].split()
            ]
        except IndexError:
            secret = []
        pairs.append((key, secret))
    return pairs


def interactive_input():
    print("Interactive mode detected. Follow the prompts below to enter data.")
    n = int(input("Number of key/secret pairs: "))
    pairs = []
    for i in range(n):
        key = input(f"Key {i + 1}: ")
        key = "".join([c for c in key.strip().upper() if c.isalpha()])
        secret = input(f"Ciphertext {i + 1} (space-separated): ").split()
        secret = [
            "".join([c for c in w.strip().upper() if c.isalpha()]) for w in secret
        ]
        pairs.append((key, secret))
    return pairs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keyword Transposition Cipher CLI")
    parser.add_argument(
        "-e",
        "--encrypt",
        "--encode",
        dest="encrypt",
        action="store_true",
        help="Encrypt plaintext instead of decrypting ciphertext",
    )
    parser.add_argument(
        "-d",
        "--decrypt",
        dest="decrypt",
        action="store_true",
        help="Explicitly decrypt ciphertext (default)",
    )
    parser.add_argument(
        "--map",
        dest="show_map",
        action="store_true",
        default=False,
        help="Print alphabet mapping used for provided key",
    )
    parser.add_argument(
        "--key",
        dest="key",
        help="Key for a single pair (avoid interactive prompts)",
    )
    parser.add_argument(
        "--secret",
        dest="secret",
        help="Secret for a single pair (space separated words), use quotes if spaces",
    )
    args, unknown = parser.parse_known_args()
    # If key and secret were provided via flags, use them
    if args.key and args.secret:
        skey = "".join([c for c in args.key.strip().upper() if c.isalpha()])
        ssecret = [
            "".join([c for c in w.strip().upper() if c.isalpha()])
            for w in args.secret.split()
        ]
        pairs = [(skey, ssecret)]
    else:
        # If running interactively (attached to a TTY) show prompts and help text.
        if sys.stdin.isatty():
            pairs = interactive_input()
        else:
            pairs = parse_piped_input()

    if not pairs:
        print("No valid input detected. See README.md for usage examples.")
        sys.exit(1)

    # Decode or encode each key/secret pair individually and print results per-case
    for key, secret in pairs:
        KeywordTranspositionCipher.ALPHA = KeywordTranspositionCipher._ALPHA
        # show mapping if asked
        if args.show_map:
            # compute mapping
            new_alpha = KeywordTranspositionCipher.get_sub_alpha(
                KeywordTranspositionCipher.create_dict(
                    KeywordTranspositionCipher.remove_redundant(key)
                )
            )
            # print mapping as ALPHA -> NEW_ALPHA
            print("Mapping (ALPHA -> NEW_ALPHA):")
            for i, c in enumerate(KeywordTranspositionCipher._ALPHA):
                print(f"{c} -> {new_alpha[i]}")
            continue
        if args.encrypt:
            answers = KeywordTranspositionCipher.encipher(key, secret)
        else:
            answers = KeywordTranspositionCipher.decipher(key, secret)
        print(" ".join(answers))
