#!/usr/bin/env python
from __future__ import division
import collections
import os
import math
from keywordtranspositioncipher.keyword_transposition_cipher import KeywordTranspositionCipher


"""
SOLUTION TO CHALLENGE:
https://www.hackerrank.com/challenges/basic-cryptanalysis

simple dictionary attack on a cipher

TEST INPUT:
STDIN:
lhpohes gvjhe ztytwojmmtel lgsfcgver segpsltjyl vftstelc djfl rml catrroel jscvjqjyfo mjlesl lcjmmfqe egvj gsfyhtyq sjfgver csfaotyq lfxtyq gjywplesl lxljm dxcel mpyctyq ztytwojmmtelel mfcgv spres mjm psgvty bfml ofle mjlc dtc tygfycfctjy dfsyl zpygvel csfao yealqsjpml atyl lgsjql qyfsotelc fseyf ojllel gjzmselltyq wpyhtelc zpltgl weygel afyher rstnesl aefleo rtyhes mvflel yphe rstnes qojder dtwwer lojml mfcgvel reocfl djzder djpygtyq gstmmoeafsel reg cpdel qspyqe mflctel csflvtyq vfcl avfghtyq vftsdfool mzer rsjye wjjol psol mplvtyq catrroe mvfqe lgseey leqzeycer wjseqsjpyrer lmjtoes msjwtoel docl djpyger cjpstlcl goefy gojddesl mjrl qjddoe gjy gpdtyql lyftotyq rjayojfr swgl vjle atrqec gjzmfgces frfl qotcgver gspzd zftodjzdl lyfsh
FILE:
dictionary.lst
"""
HERE = os.path.dirname(os.path.realpath(__file__))
COMMON_LETTERS = ['E', 'T', 'N', 'R', 'O', 'A', 'I', 'S']
COMMON_DIGRAPH = ['TH', 'HE', 'EN', 'RE', 'ER']
COMMON_TRIGRAPH = ['THE', 'ING', 'CON', 'ENT', 'ERE']
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

class Letter(object):
    total_count = 0
    letter = ''

    def __init__(self, letter):
        self.letter = letter

class BasicCryptanalysis(object):

    def __init__(self, **kwargs):
        self.results = collections.OrderedDict()
        self.used_keys = []
        self.letter_roughness = 0.0

        self.prepare_secrets()
        self.prepare_answers()
        self.prepare_dictionary()

        self.crypt_alpha = collections.OrderedDict()
        for a in ALPHABET:
            self.crypt_alpha[a] = '*'

        self.matches = collections.OrderedDict()
        for secret in self.prepared_secrets[0]:
            self.matches[secret] = []
        self.certinty_threshold = kwargs.get('certinty_threshold', 0.99)

    def prepare_secrets(self):
        secrets = 'lhpohes gvjhe ztytwojmmtel lgsfcgver segpsltjyl vftstelc djfl rml catrroel jscvjqjyfo mjlesl lcjmmfqe egvj gsfyhtyq sjfgver csfaotyq lfxtyq gjywplesl lxljm dxcel mpyctyq ztytwojmmtelel mfcgv spres mjm psgvty bfml ofle mjlc dtc tygfycfctjy dfsyl zpygvel csfao yealqsjpml atyl lgsjql qyfsotelc fseyf ojllel gjzmselltyq wpyhtelc zpltgl weygel afyher rstnesl aefleo rtyhes mvflel yphe rstnes qojder dtwwer lojml mfcgvel reocfl djzder djpygtyq gstmmoeafsel reg cpdel qspyqe mflctel csflvtyq vfcl avfghtyq vftsdfool mzer rsjye wjjol psol mplvtyq catrroe mvfqe lgseey leqzeycer wjseqsjpyrer lmjtoes msjwtoel docl djpyger cjpstlcl goefy gojddesl mjrl qjddoe gjy gpdtyql lyftotyq rjayojfr swgl vjle atrqec gjzmfgces frfl qotcgver gspzd zftodjzdl lyfsh'
        # secrets = 'l dxtw kxdtlnb sfxbfoiilnb hgoddwnbwk'
        # secrets = 'jhqsuxfxbq'
        self.prepared_secrets = self.prepare_words(secrets)

    def prepare_answers(self):
        answers = 'skulker choke minifloppies scratched recursions hairiest boas dps twiddles orthogonal posers stoppage echo cranking roached trawling saying confusers sysop bytes punting minifloppieses patch ruder pop urchin zaps lase post bit incantation barns munches trawl newsgroups wins scrogs gnarliest arena losses compressing funkiest musics fences wanked drivers weasel dinker phases nuke driver globed biffed slops patches deltas bombed bouncing cripplewares dec tubes grunge pasties trashing hats whacking hairballs pmed drone fools urls pushing twiddle phage screen segmented foregrounded spoiler profiles blts bounced tourists clean clobbers pods gobble con cubings snailing download rfcs hose widget compacter adas glitched crumb mailbombs snark'
        # answers = 'i love solving programming challenges'
        # answers = 'cryptology'
        self.prepared_answers = self.prepare_words(answers)

    def prepare_words(self, words):
        n = 5
        words = words.upper().strip()
        return [words.split(' ')]
        # words = words.replace(' ', '')
        # return [[words[i:i+n] for i in range(0, len(words), n)]]

    def prepare_dictionary(self):
        with open(os.path.join(HERE, 'dictionary.lst')) as f:
            lines = f.readlines()
        self.prepared_dictionary = [l.upper().strip() for l in lines]

    def run(self):
        running = True
        new_prepared_dict = self.prepared_dictionary
        newk = ''
        pairs = []

        self.second_pass_match(
            list(set(
                self.first_pass_match()
            ))
        )

        matched = []
        matched_crypted = []
        for i,v in enumerate(self.matches):
            matched.append(self.matches[v][0])
            matched_crypted.append(v)
        # decrypted = ' '.join(matched)
        answers = ' '.join(self.prepared_answers[0]).strip()

        decrypted = self.decipher_with_alphabet().strip()

        print decrypted.lower()


    def decipher_with_alphabet(self):
        deciphered = ''
        for secret in self.prepared_secrets[0]:
            for a in secret:
                dec = '*'
                for k,v in enumerate(self.crypt_alpha):
                    if self.crypt_alpha[v] == a:
                        dec = v
                deciphered += dec
            deciphered += ' '
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

        for k,v in enumerate(self.crypt_alpha):
            if self.crypt_alpha[v] != '*' and self.crypt_alpha[v] == val:
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
        self.alpha_str = ''
        for a in self.crypt_alpha:
            self.alpha_str += self.crypt_alpha[a]

    """
    Iterate over matches with multiple answers and determine
    correct answer using new alphabet.
    """
    def second_pass_match(self, secrets):
        unmatched_words = []
        matched_crypts = []
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
                    for i, a in enumerate(matched_word):
                        if self.crypt_alpha[a] == '*':
                            self.crypt_alpha[a] = secret[i]

                    self.matches[secret] = [matched_word]
                else:
                    self.matches[secret] = matched_words
                self.build_alphabet(matched_crypt)
        return self.prepared_secrets[0]

    def get_new_word(self, uw, match):
        missing_letters = False
        new_word = ''

        for a,l in enumerate(uw):
            try:
                new_word += ALPHABET[self.alpha_str.index(l)]
            except ValueError:
                new_word += '*'
                missing_letters = True

        if missing_letters:
            new_word = self.identify_missing_letters(
                new_word, match, uw
            )

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
        new_word_2 = ''
        # self.new_letters = {}
        for n, a in enumerate(word):
            if self.crypt_alpha[match[n]] == '*':
                new_word_2 += match[n]
                # new_letters[match[n]] = uw[n]
            else:
                new_word_2 += a
        return new_word_2
