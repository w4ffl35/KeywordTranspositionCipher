#!/usr/bin/env python3
"""
SOLUTION TO CHALLENGE:
https://www.hackerrank.com/challenges/basic-cryptanalysis

Given a piece of text encoded with a simple monoalphabetic substitution cipher,
use basic cryptanalytic techniques to recover the original plain text.
"""

from __future__ import division
import collections
import os
from typing import Dict, List, Optional

from keywordtranspositioncipher.keyword_transposition_cipher import (
    KeywordTranspositionCipher,
)


HERE = os.path.dirname(os.path.realpath(__file__))
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class Letter:
    """Represents a letter with associated frequency count."""

    def __init__(self, letter: str):
        """Initialize a Letter object.

        Args:
            letter: Single character letter
        """
        self.letter = letter
        self.total_count = 0


class BasicCryptanalysis:
    """Monoalphabetic substitution cipher solver using pattern matching."""

    def __init__(self, secrets: Optional[str] = None, **kwargs):
        """Initialize BasicCryptanalysis solver.

        Args:
            secrets: Optional ciphertext string (if None, reads from stdin)
            **kwargs: Additional options (certinty_threshold)
        """
        self.results: Dict = collections.OrderedDict()
        self.used_keys: List = []
        self.letter_roughness = 0.0

        # allow providing secrets programmatically for tests
        self.prepare_secrets(secrets)
        self.prepare_dictionary()

        self.crypt_alpha: Dict[str, str] = collections.OrderedDict()
        for a in ALPHABET:
            self.crypt_alpha[a] = "*"

        self.matches: Dict[str, List[str]] = collections.OrderedDict()
        for secret in self.prepared_secrets[0]:
            self.matches[secret] = []
        self.certinty_threshold = kwargs.get("certinty_threshold", 0.99)

    def prepare_secrets(self, secrets: Optional[str] = None) -> None:
        """Prepare secrets from input string or stdin.

        Args:
            secrets: Optional ciphertext input
        """
        if secrets is None:
            secrets = input()
        if isinstance(secrets, (list, tuple)):
            secrets = " ".join(secrets)
        self.prepared_secrets = self.prepare_words(secrets)

    def prepare_words(self, words: str) -> List[List[str]]:
        """Prepare and normalize word list.

        Args:
            words: Space-separated word string

        Returns:
            List of lists containing uppercase words
        """
        words = words.upper().strip()
        return [words.split(" ")]

    def prepare_dictionary(self) -> None:
        """Load dictionary from file and normalize to uppercase."""
        with open(os.path.join(HERE, "dictionary.lst"), encoding="utf-8") as f:
            lines = f.readlines()
        self.prepared_dictionary = [l.upper().strip() for l in lines]

    def execute(self) -> str:
        """Execute cryptanalysis and return decrypted text.

        Returns:
            Lowercased decrypted plaintext string
        """
        self.second_pass_match(list(set(self.first_pass_match())))

        decrypted = self.decipher_with_alphabet().strip().lower()

        try:
            print(decrypted)
        except Exception:
            pass

        return decrypted

    @classmethod
    def run(cls, keys: List[str], secret_sets: List) -> List:
        """Run analysis for keys and secret sets (test compatibility method).

        Args:
            keys: List of cipher keys
            secret_sets: List of ciphertext sets

        Returns:
            List of decrypted result lists
        """
        KeywordTranspositionCipher.ALPHA = KeywordTranspositionCipher._ALPHA
        results = []
        for i in range(min(len(keys), len(secret_sets))):
            key = keys[i]
            secret_set = secret_sets[i]
            if isinstance(secret_set, (list, tuple)):
                if len(secret_set) == 1 and " " in secret_set[0]:
                    secrets = secret_set[0].split(" ")
                else:
                    secrets = list(secret_set)
            else:
                secrets = secret_set.split(" ")

            results.append(KeywordTranspositionCipher.decipher(key, secrets))
        return [results]

    def decipher_with_alphabet(self) -> str:
        """Decipher ciphertext using current alphabet mapping.

        Returns:
            Decrypted string with unmapped characters as '*'
        """
        deciphered = ""
        for secret in self.prepared_secrets[0]:
            for a in secret:
                dec = "*"
                for v in self.crypt_alpha:
                    if self.crypt_alpha[v] == a:
                        dec = v
                deciphered += dec
            deciphered += " "
        return deciphered

    def first_pass_match(self) -> List[str]:
        """Find dictionary matches using pattern matching.

        Returns:
            List of ciphertext words processed
        """
        used_secrets = []
        for secret_set in self.prepared_secrets:
            for secret in secret_set:
                for word in self.prepared_dictionary:
                    if len(secret) == len(word):
                        if self.certinty(secret, word) >= self.certinty_threshold:
                            self.matches[secret].append(word)
                            used_secrets.append(secret)
        self.build_alphabet(used_secrets)
        return self.prepared_secrets[0]

    def assign_crypt_alpha(self, key: str, val: str) -> None:
        """Assign a cipher mapping if not already assigned.

        Args:
            key: Plaintext letter
            val: Ciphertext letter
        """
        matched = False
        for v in self.crypt_alpha:
            if self.crypt_alpha[v] != "*" and self.crypt_alpha[v] == val:
                matched = True
        if not matched:
            self.crypt_alpha[key] = val

    def build_alphabet(self, secrets: List[str]) -> None:
        """Build cipher alphabet mapping from matched secrets.

        Args:
            secrets: List of ciphertext words with unique matches
        """
        for secret in secrets:
            if len(self.matches[secret]) == 1:
                for a, l in enumerate(self.matches[secret][0]):
                    self.assign_crypt_alpha(l, secret[a])
        self.build_alphabet_string()

    def build_alphabet_string(self) -> None:
        """Build string representation of current cipher alphabet."""
        self.alpha_str = ""
        for a in self.crypt_alpha:
            self.alpha_str += self.crypt_alpha[a]

    def second_pass_match(self, secrets: List[str]) -> List[str]:
        """Refine matches using partially built alphabet.

        Args:
            secrets: List of ciphertext words to refine

        Returns:
            List of processed secrets
        """
        for secret in secrets:
            if len(self.matches[secret]) > 1:
                matched_words = []
                matched_crypt = []
                matched_word = None

                for match in self.matches[secret]:
                    if not matched_word:
                        new_word = self.get_new_word(secret, match)
                        if new_word == match:
                            matched_word = match
                    matched_crypt.append(secret)
                    matched_words.append(match)

                if matched_word and new_word == matched_word:
                    self.matches[secret] = [matched_word]
                else:
                    self.matches[secret] = matched_words
                self.build_alphabet(matched_crypt)
        return self.prepared_secrets[0]

    def get_new_word(self, uw: str, match: str) -> str:
        """Decrypt a ciphertext word using current alphabet.

        Args:
            uw: Ciphertext word
            match: Candidate plaintext match

        Returns:
            Decrypted word with '*' for unknown letters
        """
        missing_letters = False
        new_word = ""
        for l in uw:
            try:
                new_word += ALPHABET[self.alpha_str.index(l)]
            except ValueError:
                new_word += "*"
                missing_letters = True
        if missing_letters:
            new_word = self.identify_missing_letters(new_word, match, uw)
        return new_word

    def certinty(self, secret: str, word: str) -> float:
        """Calculate pattern matching certainty between cipher and plain word.

        Args:
            secret: Ciphertext word
            word: Plaintext candidate

        Returns:
            Certainty score (0.0 to 1.0)
        """
        certinty_score = float(0)
        uniq_letters_crypt: List[str] = []
        uniq_letters_plaintext: List[str] = []
        n = 1 / len(secret)
        for i in enumerate(secret):
            if secret[i[0]] not in uniq_letters_crypt:
                uniq_letters_crypt.append(secret[i[0]])
            if word[i[0]] not in uniq_letters_plaintext:
                uniq_letters_plaintext.append(word[i[0]])
            freq_crypt = self.get_letter_frequency_in_word(
                word=secret, letter=secret[i[0]]
            )
            freq_plaintext = self.get_letter_frequency_in_word(
                word=word, letter=word[i[0]]
            )
            if freq_crypt == freq_plaintext:
                certinty_score += n
        return round(certinty_score, 2)

    def get_letter_frequency_in_word(self, word: str, letter: str) -> float:
        """Calculate frequency of a letter in a word.

        Args:
            word: Word to analyze
            letter: Letter to count

        Returns:
            Frequency ratio (0.0 to 1.0)
        """
        total_count = len(word)
        freq = 0
        for l in word:
            if l == letter:
                freq += 1
        return freq / total_count

    def identify_missing_letters(self, word: str, match: str, uw: str) -> str:
        """Fill in gaps in deciphered text using potential match.

        Args:
            word: Partially decrypted word with '*' gaps
            match: Candidate plaintext match
            uw: Original ciphertext word

        Returns:
            Word with gaps filled where possible
        """
        new_word_2 = ""
        for n, a in enumerate(word):
            if self.crypt_alpha[match[n]] == "*":
                new_word_2 += match[n]
            else:
                new_word_2 += a
        return new_word_2


if __name__ == "__main__":
    bc = BasicCryptanalysis()
    bc.execute()
