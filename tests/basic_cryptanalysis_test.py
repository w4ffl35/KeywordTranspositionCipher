#!/usr/bin/env python
import unittest
from basiccryptanalysis.basic_cryptanalysis import BasicCryptanalysis


class BasicCryptanalysisTest(unittest.TestCase):
    def test_decrypt(self):
        lines = BasicCryptanalysis.run(
            ['SPORT'],
            ['LDXTW KXDTL NBSFX BFOII LNBHG ODDWN BWK']
        )

        self.assertEqual(
            lines[0],
            ['ILOVE', 'SOLVI', 'NGPRO', 'GRAMM', 'INGCH', 'ALLEN', 'GES']
        )


if __name__ == '__main__':
    unittest.main()
