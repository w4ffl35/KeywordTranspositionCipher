#!/usr/bin/env python3
"""
SOLUTION TO CHALLENGE:
https://www.hackerrank.com/challenges/keyword-transposition-cipher

Given a key, solves a monoalphabetic substitution cipher.

TEST INPUT:
2
SPORT
LDXTW KXDTL NBSFX BFOII LNBHG ODDWN BWK
SECRET
JHQSU XFXBQ
"""

import collections
from typing import Dict, List, Optional, Union


class KeywordTranspositionCipher:
    """Monoalphabetic substitution cipher using keyword transposition."""

    _ALPHA: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ALPHA: str = ""
    NEW_ALPHA: Optional[str] = None

    @classmethod
    def run(
        cls, keys: List[str], secret_sets: List, new_alpha: Optional[str] = None
    ) -> Dict[str, List[str]]:
        """Run cipher decryption for multiple keys and secret sets.

        Args:
            keys: List of cipher keys
            secret_sets: List of ciphertext word sets
            new_alpha: Optional custom substitution alphabet

        Returns:
            Dictionary mapping keys to decrypted word lists
        """
        cls.ALPHA = cls._ALPHA
        if new_alpha:
            cls.NEW_ALPHA = new_alpha

        lines: Dict[str, List[str]] = {}
        for i, secrets in enumerate(secret_sets):
            for key in keys:
                lines[key] = cls.decipher(key, secrets)
        return lines

    @classmethod
    def _normalize_key(cls, key: Optional[str]) -> str:
        """Normalize key to uppercase alpha characters.

        Args:
            key: Raw key string or None

        Returns:
            Normalized key string
        """
        if key is None:
            key = ""
        return "".join([c for c in key.upper() if c.isalpha()])

    @classmethod
    def _normalize_secrets(cls, secrets: Union[str, List[str]]) -> List[str]:
        """Normalize secrets to uppercase alpha words.

        Args:
            secrets: Raw secret string or list

        Returns:
            List of normalized secret words
        """
        if isinstance(secrets, (list, tuple)):
            return ["".join([c for c in s.upper() if c.isalpha()]) for s in secrets]
        return ["".join([c for c in secrets.upper() if c.isalpha()])]

    @classmethod
    def decipher(cls, key: Optional[str], secrets: Union[str, List[str]]) -> List[str]:
        """Decipher ciphertext using keyword transposition.

        Args:
            key: Cipher key (or None)
            secrets: Ciphertext string or list of words

        Returns:
            List of decrypted plaintext words
        """
        # Ensure the working alphabet is initialized
        if not cls.ALPHA:
            cls.ALPHA = cls._ALPHA

        key = cls._normalize_key(key)
        secrets_list = cls._normalize_secrets(secrets)

        alpha_sub = cls.get_sub_alpha(cls.create_dict(cls.remove_redundant(key)))
        cls.NEW_ALPHA = alpha_sub

        answers: List[str] = list(secrets_list)
        for i, secret in enumerate(secrets_list):
            word = ""
            for alpha in secret:
                alpha = alpha.upper()
                if alpha not in cls.ALPHA:
                    word += alpha
                    continue
                try:
                    idx = cls.NEW_ALPHA.index(alpha)
                    word += cls._ALPHA[idx]
                except (ValueError, AttributeError):
                    word += "*"
            answers[i] = word
        cls.ANSWERS = answers

        return answers

    @classmethod
    def encipher(cls, key: Optional[str], secrets: Union[str, List[str]]) -> List[str]:
        """Encipher plaintext using keyword transposition.

        Args:
            key: Cipher key (or None)
            secrets: Plaintext string or list of words

        Returns:
            List of encrypted ciphertext words
        """
        # Normalize key and secrets and ensure ALPHA set
        if not cls.ALPHA:
            cls.ALPHA = cls._ALPHA

        key = cls._normalize_key(key)
        secrets_list = cls._normalize_secrets(secrets)

        # Compute the NEW_ALPHA based on the provided key
        cls.NEW_ALPHA = cls.get_sub_alpha(cls.create_dict(cls.remove_redundant(key)))

        answers: List[str] = list(secrets_list)
        for i, secret in enumerate(secrets_list):
            word = ""
            for alpha in secret:
                alpha = alpha.upper()
                if alpha in cls._ALPHA:
                    idx = cls._ALPHA.index(alpha)
                    word += cls.NEW_ALPHA[idx]
                else:
                    word += alpha
            answers[i] = word
        return answers

    @classmethod
    def remove_redundant(cls, inp: str) -> List[str]:
        """Remove duplicate characters from input, preserving order.

        Args:
            inp: Input string

        Returns:
            List of unique characters in order
        """
        output: List[str] = []
        for char in inp:
            if char not in output:
                output.append(char)
        return output

    @classmethod
    def create_dict(cls, key: List[str]) -> "collections.OrderedDict[str, List[str]]":
        """Create substitution alphabet dictionary from key.

        Args:
            key: List of key characters

        Returns:
            OrderedDict mapping key chars to remaining alphabet chars
        """
        alpha = list(cls.ALPHA)

        newalpha_dict: "collections.OrderedDict[str, List[str]]" = (
            collections.OrderedDict()
        )
        for k in key:
            if k in alpha:
                alpha.remove(k)
            newalpha_dict[k] = []

        i = 0
        for a in cls.ALPHA:
            if i >= len(key):
                i = 0
            k = key[i]
            if a not in key:
                newalpha_dict[k].append(a)
                i += 1
        return newalpha_dict

    @classmethod
    def get_sub_alpha(cls, cipher_dict: Dict[str, List[str]]) -> str:
        """Generate substitution alphabet from cipher dictionary.

        Args:
            cipher_dict: Dictionary from create_dict

        Returns:
            Substitution alphabet string
        """
        keys = list(cipher_dict.keys())
        keys.sort()
        reordered = ""
        for a in keys:
            reordered += a
            for k in cipher_dict[a]:
                if k not in reordered:
                    reordered += k
        return reordered
