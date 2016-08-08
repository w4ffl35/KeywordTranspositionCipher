#!/usr/bin/env python


import unittest
from keywordtranspositioncipher.keyword_transposition_cipher import KeywordTranspositionCipher


class KeywordTranspositionCipherTest(unittest.TestCase):
    KEY = ['SECRET']
    SECRET_SETS = [['JHQSU', 'XFXBQ']]
    # ANSWERS = [['CRYPT', 'OLOGY']]
    ANSWERS = [['LDXTW', 'KXDTL', 'NBSFX', 'BFOII', 'LNBHG', 'ODDWN', 'BWK']]
    NEW_ALPHA = 'CDJOWEBINVRFKPXSAHMUZTGLQY'

    def test_remove_redundant(self):
        self.assertEqual(
            'SECRT',
            ''.join(
                KeywordTranspositionCipher.remove_redundant(
                    self.KEY[0]
                )
            )
        )

    def test_alphabet(self):
        lines = KeywordTranspositionCipher.run(
            self.KEY,
            self.SECRET_SETS
        )

        self.assertEqual(
            KeywordTranspositionCipher.NEW_ALPHA,
            self.NEW_ALPHA
        )

    def test_decrypt(self):
        lines = KeywordTranspositionCipher.run(
            self.KEY,
            self.SECRET_SETS
        )

        self.assertEqual(
            lines,
            self.ANSWERS
        )

if __name__ == '__main__':
    unittest.main()
