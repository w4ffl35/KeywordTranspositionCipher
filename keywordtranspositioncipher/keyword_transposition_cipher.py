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
    _ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ALPHA = []
    NEW_ALPHA = None

    @classmethod
    def run(cls, keys, secret_sets, new_alpha=None):
        cls.ALPHA = cls._ALPHA
        if new_alpha:
            cls.NEW_ALPHA = new_alpha

        lines = {}
        for i, secrets in enumerate(secret_sets):
            for key in keys:
                lines[key] = cls.decipher(key, secrets)
        return lines

    @classmethod
    def decipher(cls, key, secrets):
        # Ensure the working alphabet is initialized
        if not cls.ALPHA:
            cls.ALPHA = cls._ALPHA

        # Normalize key and secrets to uppercase, filter non-alpha characters
        if key is None:
            key = ""
        key = "".join([c for c in key.upper() if c.isalpha()])
        if isinstance(secrets, (list, tuple)):
            secrets = ["".join([c for c in s.upper() if c.isalpha()]) for s in secrets]
        else:
            secrets = ["".join([c for c in secrets.upper() if c.isalpha()])]

        alpha_sub = cls.get_sub_alpha(cls.create_dict(cls.remove_redundant(key)))
        cls.NEW_ALPHA = alpha_sub

        answers = list(secrets)
        for i, secret in enumerate(secrets):
            word = ""
            for a, alpha in enumerate(secret):
                # Looking up the index in NEW_ALPHA may raise ValueError; handle
                # unknown letters gracefully by appending a placeholder.
                alpha = alpha.upper()
                if alpha not in cls.ALPHA:
                    word += alpha
                    continue
                try:
                    idx = cls.NEW_ALPHA.index(alpha)
                    word += cls._ALPHA[idx]
                except ValueError:
                    # if letter not found in NEW_ALPHA try to append placeholder
                    word += "*"
            answers[i] = word
        cls.ANSWERS = answers

        return answers

    @classmethod
    def encipher(cls, key, secrets):
        # NOTE: encipher expects that the cls.NEW_ALPHA has already been set
        # for the desired key (for backwards compatibility we keep the
        # signature simple). This method will transform a list/tuple of
        # plaintext words to their ciphertext forms using the currently set
        # NEW_ALPHA.
        # Normalize key and secrets and ensure ALPHA set
        if not cls.ALPHA:
            cls.ALPHA = cls._ALPHA
        if key is None:
            key = ""
        key = "".join([c for c in key.upper() if c.isalpha()])
        if isinstance(secrets, (list, tuple)):
            secrets = ["".join([c for c in s.upper() if c.isalpha()]) for s in secrets]
        else:
            secrets = ["".join([c for c in secrets.upper() if c.isalpha()])]

        # Compute the NEW_ALPHA based on the provided key
        cls.NEW_ALPHA = cls.get_sub_alpha(cls.create_dict(cls.remove_redundant(key)))

        answers = list(secrets)
        for i, secret in enumerate(secrets):
            word = ""
            for alpha in secret:
                alpha = alpha.upper()
                if alpha in cls._ALPHA:
                    idx = cls._ALPHA.index(alpha)
                    word += cls.NEW_ALPHA[idx]
                else:
                    # keep unknown characters unchanged
                    word += alpha
            answers[i] = word
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
        # Convert keys view to list for Python 3 compatibility and sort
        keys = list(c.keys())
        keys.sort()
        reordered = ""
        for a in keys:
            reordered += a
            for k in c[a]:
                if k not in reordered:
                    reordered += k
        return reordered
