import collections


"""
SOLUTION TO CHALLENGE:
https://www.hackerrank.com/challenges/keyword-transposition-cipher

given a key, solves a monoalphabetic substitution cipher

TEST INPUT:
2
SPORT
LDXTW KXDTL NBSFX BFOII LNBHG ODDWN BWK
SECRET
JHQSU XFXBQ
"""
class KeywordTranspositionCipher(object):
    _ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ALPHA = []
    NEW_ALPHA = None

    @classmethod
    def run(cls, keys, secret_sets, new_alpha=None):
        cls.ALPHA = cls._ALPHA
        if new_alpha:
            cls.NEW_ALPHA = new_alpha

        lines = []
        for secrets in secret_sets:
            for key in keys:
                lines.append(cls.dcrypt(key, secrets))
        return lines

    @classmethod
    def dcrypt(cls, key, secrets):
        alpha_sub = cls.get_sub_alpha(
            cls.create_dict(cls.remove_redundant(key))
        )
        cls.NEW_ALPHA = alpha_sub

        answers = list(secrets)
        for i, secret in enumerate(secrets):
            word = ''
            for a, alpha in enumerate(secret):
                cls.ALPHA.index(alpha)
                cls._ALPHA[cls.ALPHA.index(alpha)]
                word += cls._ALPHA[cls.NEW_ALPHA.index(alpha)]
            answers[i] = word
        cls.ANSWERS = answers

        return answers

    @classmethod
    def remove_redundant(cls, inp):
        o = []
        inp = list(inp)
        for i in inp:
            if i not in o:
                o.append(i)
        return o

    @classmethod
    def create_dict(cls, key):
        alpha = list(cls.ALPHA)

        newalpha_dict = collections.OrderedDict()
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
