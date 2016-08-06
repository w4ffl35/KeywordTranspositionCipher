#!/usr/bin/env python


import unittest
from keyword_transposition_cipher import KeywordTranspositionCipher


class KeywordTranspositionCipherTest(unittest.TestCase):
    def test_decrypt(self):
        lines = KeywordTranspositionCipher.run(
            ['SPORT'],
            ['LDXTW KXDTL NBSFX BFOII LNBHG ODDWN BWK']
        )

        self.assertEqual(
            lines[0],
            ['ILOVE', 'SOLVI', 'NGPRO', 'GRAMM', 'INGCH', 'ALLEN', 'GES']
        )

if __name__ == '__main__':
    unittest.main()