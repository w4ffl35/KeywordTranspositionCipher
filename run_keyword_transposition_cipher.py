#!/usr/bin/env python
from keywordtranspositioncipher.keyword_transposition_cipher import KeywordTranspositionCipher


if __name__ == '__main__':
    n = int(raw_input())
    crypts = []
    secrets = []
    for i in range(n):
        crypts.append(raw_input())
        secrets.append(raw_input().split(' '))
    lines = KeywordTranspositionCipher.run(crypts, secrets)
    for l in lines:
        print ' '.join(l)
