#!/usr/bin/env python
import collections


# crypt_a = 'SPORT'
# secret_a = 'LDXTW KXDTL NBSFX BFOII LNBHG ODDWN BWK'
# crypt_b = 'SECRET'
# secret_b = 'JHQSU XFXBQ'

ALPHA = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')

class KeywordTranspositionCipher(object):
    def __init__(self, crypts, secrets):
        lines = []
        for i, c in enumerate(crypts):
            lines.append(self.dcrypt(c, secrets[i]))
        self.display(lines)

    def dcrypt(self, c, s):
        s = s.split(' ')
        c = self.create_dict(self.remove_redundant(c))
        alpha_sub = self.get_sub_alpha(c)

        words = []
        for w in s:
            word = ''
            for i,a in enumerate(w):
                word += ALPHA[alpha_sub.index(a)]
            words.append(word)
        return words

    def remove_redundant(self, inp):
        o = []
        inp = list(inp)
        for i in inp:
            if i not in o:
                o.append(i)
        return o

    def create_dict(self, c):
        key = collections.OrderedDict()
        n = 0

        size = len(c)

        for a in c:
            key[a] = []

        for a in ALPHA:
            if a not in key.keys():
                key[key.keys()[n]].append(a)
                n += 1
            if n == size:
                n = 0
        return key

    def get_sub_alpha(self, c):
        keys = c.keys()
        keys.sort()
        reordered = ""
        for a in keys:
            reordered += a
            for k in c[a]:
                if k not in reordered:
                    reordered += k
        return reordered

    def display(self, lines):
        for l in lines:
            print ' '.join(l)


if __name__ == '__main__':
    n = int(raw_input())
    crypts = []
    secrets = []
    for i in range(n):
        crypts.append(raw_input())
        secrets.append(raw_input())
    ktc = KeywordTranspositionCipher(crypts, secrets)
