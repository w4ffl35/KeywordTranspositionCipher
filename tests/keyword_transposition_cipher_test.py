#!/usr/bin/env python
import os
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(HERE, "..", "."))
from keywordtranspositioncipher.keyword_transposition_cipher import (
    KeywordTranspositionCipher,
)


class KeywordTranspositionCipherTest(unittest.TestCase):
    KEY = ["SECRET"]
    SECRET_SETS = [["JHQSU", "XFXBQ"]]
    ANSWERS = {"SECRET": ["CRYPT", "OLOGY"]}
    # ANSWERS = [['LDXTW', 'KXDTL', 'NBSFX', 'BFOII', 'LNBHG', 'ODDWN', 'BWK']]
    NEW_ALPHA = "CDJOWEBINVRFKPXSAHMUZTGLQY"

    def test_remove_redundant(self):
        self.assertEqual(
            "SECRT", "".join(KeywordTranspositionCipher.remove_redundant(self.KEY[0]))
        )

    def test_alphabet(self):
        lines = KeywordTranspositionCipher.run(self.KEY, self.SECRET_SETS)

        self.assertEqual(KeywordTranspositionCipher.NEW_ALPHA, self.NEW_ALPHA)

    def test_decrypt(self):
        lines = KeywordTranspositionCipher.run(self.KEY, self.SECRET_SETS)

        self.assertEqual(lines, self.ANSWERS)

    def test_encipher(self):
        # Verify that encipher produces the expected ciphertext for a known
        # plaintext/key pair (reverse of the decrypt test)
        enc = KeywordTranspositionCipher.encipher(self.KEY[0], self.ANSWERS["SECRET"])
        self.assertEqual(enc, self.SECRET_SETS[0])


if __name__ == "__main__":
    unittest.main()
