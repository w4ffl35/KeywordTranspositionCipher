#!/usr/bin/env python
import collections



"""
SOLUTION TO CHALLENGE:
https://www.hackerrank.com/challenges/keyword-transposition-cipher

TEST INPUT:
2
SPORT
LDXTW KXDTL NBSFX BFOII LNBHG ODDWN BWK
SECRET
JHQSU XFXBQ
"""
class KeywordTranspositionCipher(object):
    ALPHA = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')

    @classmethod
    def run(cls, crypts, secrets):
        lines = []
        print crypts
        for i, c in enumerate(crypts):
            lines.append(cls.dcrypt(c, secrets[i]))
        cls.display(lines)

    @classmethod
    def dcrypt(cls, c, s):
        s = s.split(' ')
        c = cls.create_dict(cls.remove_redundant(c))
        alpha_sub = cls.get_sub_alpha(c)

        words = []
        for w in s:
            word = ''
            for i,a in enumerate(w):
                word += KeywordTranspositionCipher.ALPHA[alpha_sub.index(a)]
            words.append(word)
        return words

    @classmethod
    def remove_redundant(cls, inp):
        o = []
        inp = list(inp)
        for i in inp:
            if i not in o:
                o.append(i)
        return o

    @classmethod
    def create_dict(cls, c):
        key = collections.OrderedDict()
        n = 0

        size = len(c)

        for a in c:
            key[a] = []

        for a in KeywordTranspositionCipher.ALPHA:
            if a not in key.keys():
                key[key.keys()[n]].append(a)
                n += 1
            if n == size:
                n = 0
        return key

    @classmethod
    def get_sub_alpha(cls, c):
        keys = c.keys()
        keys.sort()
        reordered = ""
        for a in keys:
            reordered += a
            for k in c[a]:
                if k not in reordered:
                    reordered += k
        return reordered

    @classmethod
    def display(cls, lines):
        for l in lines:
            print ' '.join(l)


if __name__ == '__main__':
    n = int(raw_input())
    crypts = []
    secrets = []
    for i in range(n):
        crypts.append(raw_input())
        secrets.append(raw_input())
    KeywordTranspositionCipher(crypts, secrets)

