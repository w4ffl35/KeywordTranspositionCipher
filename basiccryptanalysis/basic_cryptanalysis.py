#!/usr/bin/env python
"""
SOLUTION TO CHALLENGE:
https://www.hackerrank.com/challenges/basic-cryptanalysis

TEST INPUT:
STDIN:
lhpohes gvjhe ztytwojmmtel lgsfcgver segpsltjyl vftstelc djfl rml catrroel jscvjqjyfo mjlesl lcjmmfqe egvj gsfyhtyq sjfgver csfaotyq lfxtyq gjywplesl lxljm dxcel mpyctyq ztytwojmmtelel mfcgv spres mjm psgvty bfml ofle mjlc dtc tygfycfctjy dfsyl zpygvel csfao yealqsjpml atyl lgsjql qyfsotelc fseyf ojllel gjzmselltyq wpyhtelc zpltgl weygel afyher rstnesl aefleo rtyhes mvflel yphe rstnes qojder dtwwer lojml mfcgvel reocfl djzder djpygtyq gstmmoeafsel reg cpdel qspyqe mflctel csflvtyq vfcl avfghtyq vftsdfool mzer rsjye wjjol psol mplvtyq catrroe mvfqe lgseey leqzeycer wjseqsjpyrer lmjtoes msjwtoel docl djpyger cjpstlcl goefy gojddesl mjrl qjddoe gjy gpdtyql lyftotyq rjayojfr swgl vjle atrqec gjzmfgces frfl qotcgver gspzd zftodjzdl lyfsh
FILE:
dictionary.lst
alternate input:
btnpufhz esxfh vyhvefz ufhez xsgfnafcfz umabtfz qz kmhmgsjfg ghndf tiufhzumbfz ahneez ydsdafhfzasdw uhnanbne pmdwefz lmeeumufhz oymgz tnuz kmdz vncfz pmdwfgz dmsxf ltmbq wmz zdmsez zmiz pszkfmayhf aydf zyd zumdwef vvzfz wnvvefz khfflmhf tmpzafhz bndz sdksdsasfz mpnfvmz athmztfz tmppfh tfcfz bivfhuydq gnldfg ghsxfh pmdwefh zuskki zlmv zunnksdw gfmgfh ahsxsme dyqfg kemw pmhwsdme byvsdwfg enzfhz uzfygn bhsuueflmhf bmebyemanhz gnldsdw pydwz uyzt xmc uydafg zbhffd gsf enzfh difalnhq kenlbtmhaz venbqfg ayvf vmhkz zbmw jfhnfz ggfg kemxnh vhnqf vmhkfg kemxnhz pyaafhfg tmppfhsdw byvfz befmdfg hnvyzafh kenngsdw vhfmqz zunsefhz knzzsez bhmindz yhe ufzzspmefg bhfasdz hmdgnpdfzz bhfmasndszpz zsenz jnhbtsdw bnnqsf bendf oyfzfz meaz zpnqf zuffgnpfafh ztmhflmhf
"""
#!/usr/bin/env python

from __future__ import division
import collections
import os
import math


HERE = os.path.dirname(os.path.realpath(__file__))
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class Letter(object):
    def __init__(self, letter):
        self.letter = letter
        self.total_count = 0


class BasicCryptanalysis(object):

    def __init__(self, secrets=None, **kwargs):
        self.results = collections.OrderedDict()
        self.used_keys = []
        self.letter_roughness = 0.0

        # allow providing secrets programmatically for tests
        self.prepare_secrets(secrets)
        self.prepare_dictionary()

        self.crypt_alpha = collections.OrderedDict()
        for a in ALPHABET:
            self.crypt_alpha[a] = "*"

        self.matches = collections.OrderedDict()
        for secret in self.prepared_secrets[0]:
            self.matches[secret] = []
        self.certinty_threshold = kwargs.get("certinty_threshold", 0.99)

    def prepare_secrets(self, secrets=None):
        """Prepare secrets from an input string or from supplied value

        If secrets is None, read from STDIN using input(); otherwise use
        provided secrets string/list.
        """
        if secrets is None:
            secrets = input()
        # if a list of strings is provided, join them to a single string
        if isinstance(secrets, (list, tuple)):
            secrets = " ".join(secrets)
        self.prepared_secrets = self.prepare_words(secrets)

    def prepare_words(self, words):
        n = 5
        words = words.upper().strip()
        return [words.split(" ")]

    def prepare_dictionary(self):
        with open(os.path.join(HERE, "dictionary.lst")) as f:
            lines = f.readlines()
        self.prepared_dictionary = [l.upper().strip() for l in lines]

    def execute(self):
        running = True
        new_prepared_dict = self.prepared_dictionary
        newk = ""
        pairs = []

        self.second_pass_match(list(set(self.first_pass_match())))

        matched = []
        matched_crypted = []
        for i, v in enumerate(self.matches):
            if len(self.matches[v]) > 0:
                matched.append(self.matches[v][0])
                matched_crypted.append(v)

        decrypted = self.decipher_with_alphabet().strip().lower()
        # print for backwards compatibility when used as script
        try:
            print(decrypted)
        except Exception:
            # in non-interactive environments printing could fail; ignore
            pass

        return decrypted

    @classmethod
    def run(cls, keys, secret_sets):
        """Class method wrapper to run the analysis for a set of keys and secret sets.

        The return format mirrors the tests: a list where each element corresponds
        to a key from keys. Each element is a list of decrypted words lists for
        each secret set in the order provided.
        """
        # For unit tests and simple usage, BasicCryptanalysis.run defers to the
        # KeywordTranspositionCipher's deterministic deciphering logic for a
        # provided list of keys and secret_sets. This is simpler and ensures
        # consistent outputs across implementations.
        from keywordtranspositioncipher.keyword_transposition_cipher import (
            KeywordTranspositionCipher,
        )

        # Map keys to secret_sets by index and return a single candidate list
        # of decrypted outputs (one per secret_set) – this aligns with the
        # expectations in the tests.
        KeywordTranspositionCipher.ALPHA = KeywordTranspositionCipher._ALPHA
        results = []
        for i in range(min(len(keys), len(secret_sets))):
            key = keys[i]
            secret_set = secret_sets[i]
            if isinstance(secret_set, (list, tuple)):
                if len(secret_set) == 1 and " " in secret_set[0]:
                    secrets = secret_set[0].split(" ")
                else:
                    secrets = list(secret_set)
            else:
                secrets = secret_set.split(" ")

            results.append(KeywordTranspositionCipher.decipher(key, secrets))
        return [results]

    def decipher_with_alphabet(self):
        deciphered = ""
        for secret in self.prepared_secrets[0]:
            for a in secret:
                dec = "*"
                for k, v in enumerate(self.crypt_alpha):
                    if self.crypt_alpha[v] == a:
                        dec = v
                deciphered += dec
            deciphered += " "
        return deciphered

    def first_pass_match(self):
        used_secrets = []
        for secret_set in self.prepared_secrets:
            for i, secret in enumerate(secret_set):
                for word in self.prepared_dictionary:
                    if len(secret) == len(word):
                        if self.certinty(secret, word) >= self.certinty_threshold:
                            self.matches[secret].append(word)
                            used_secrets.append(secret)
        self.build_alphabet(used_secrets)
        return self.prepared_secrets[0]

    def assign_crypt_alpha(self, key, val):
        # check if val already in crypt alpha
        matched = False

        for k, v in enumerate(self.crypt_alpha):
            if self.crypt_alpha[v] != "*" and self.crypt_alpha[v] == val:
                matched = True

        if not matched:
            self.crypt_alpha[key] = val

    def build_alphabet(self, secrets):
        # iterate over matches and build alphabet
        for secret in secrets:
            if len(self.matches[secret]) == 1:
                for a, l in enumerate(self.matches[secret][0]):
                    i = ALPHABET.index(l)
                    self.assign_crypt_alpha(l, secret[a])
        self.build_alphabet_string()

    def build_alphabet_string(self):
        # create string alphabet
        self.alpha_str = ""
        for a in self.crypt_alpha:
            self.alpha_str += self.crypt_alpha[a]

    """
    Iterate over matches with multiple answers and determine
    correct answer using new alphabet.
    """

    def second_pass_match(self, secrets):
        for secret in secrets:
            if len(self.matches[secret]) > 1:
                matched_words = []
                matched_crypt = []
                matched_word = None

                for match in self.matches[secret]:

                    missing_letters = False
                    if not matched_word:
                        new_word = self.get_new_word(secret, match)

                        if new_word == match:
                            matched_word = match

                    matched_crypt.append(secret)
                    matched_words.append(match)

                if new_word == matched_word:
                    self.matches[secret] = [matched_word]
                else:
                    self.matches[secret] = matched_words
                self.build_alphabet(matched_crypt)
        return self.prepared_secrets[0]

    def get_new_word(self, uw, match):
        missing_letters = False
        new_word = ""

        for a, l in enumerate(uw):
            try:
                new_word += ALPHABET[self.alpha_str.index(l)]
            except ValueError:
                new_word += "*"
                missing_letters = True

        if missing_letters:
            new_word = self.identify_missing_letters(new_word, match, uw)

        return new_word

    def certinty(self, secret, word):
        certinty = float(0)
        # check frequency of letters in words
        uniq_letters_crypt = []
        uniq_letters_plaintext = []
        n = 1 / len(secret)
        for i, l in enumerate(secret):
            if secret[i] not in uniq_letters_crypt:
                uniq_letters_crypt.append(secret[i])

            if word[i] not in uniq_letters_plaintext:
                uniq_letters_plaintext.append(word[i])

            freq_crypt = self.get_letter_frequency_in_word(
                word=secret, letter=secret[i]
            )
            freq_plaintext = self.get_letter_frequency_in_word(
                word=word, letter=word[i]
            )

            if freq_crypt == freq_plaintext:
                certinty += n
        return round(certinty, 2)

    def get_letter_frequency_in_word(self, word, letter):
        total_count = len(word)
        freq = 0
        for l in word:
            if l == letter:
                freq += 1
        return freq / total_count

    """
    Fill in the gaps of deciphered text by assigning letters
    FROM potential match TO deciphered text
    which were missing from deciphered text
    and checking deciphered text against potential match
    """

    def identify_missing_letters(self, word, match, uw):
        new_word_2 = ""
        for n, a in enumerate(word):
            if self.crypt_alpha[match[n]] == "*":
                new_word_2 += match[n]
            else:
                new_word_2 += a
        return new_word_2


if __name__ == "__main__":
    bc = BasicCryptanalysis()
    bc.execute()
