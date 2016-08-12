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
        self.PASS = 0
        self.results = collections.OrderedDict()
        self.used_keys = []
        self.prepare_secrets()
        self.prepare_answers()
        self.prepare_dictionary()
        # self.frequency_analysis()
        self.letter_roughness = 0.0
        self.total_matches = 0
        self.alpha_str = ''
        self.crypt_alpha = collections.OrderedDict()
        self.used_words = []
        self.matches = collections.OrderedDict()
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

    def get_letter_frequency_in_word(self, word, letter):
        total_count = len(word)
        freq = 0
        for l in word:
            if l == letter:
                freq += 1
        return freq / total_count

    def run(self):
        running = True
        new_prepared_dict = self.prepared_dictionary
        newk = ''
        pairs = []

        self.first_pass_match()
        self.unique_words = list(set(self.used_words))
        self.build_alphabet()
        self.build_alphabet_string()
        self.second_pass_match()

        print self.crypt_alpha
        print '%s out of %s' % (
            self.total_matches,
            len(self.prepared_answers[0])
        )

    def first_pass_match(self):
        for secret_set in self.prepared_secrets:
            for i, secret in enumerate(secret_set):
                for word in self.prepared_dictionary:
                    if len(secret) == len(word):
                        if self.certinty(secret, word) >= self.certinty_threshold:
                            if secret not in self.matches.keys():
                                self.matches[secret] = []
                            self.matches[secret].append(word)
                            self.used_words.append(secret)

    def build_alphabet(self):
        # iterate over matches and build alphabet
        letters = {}
        for n in ALPHABET:
            self.crypt_alpha[n] = '*'
        print 'DEFINITE MATCHES:'
        for uw in self.unique_words:
            if len(self.matches[uw]) == 1:
                self.total_matches += 1
                print 'MATCH: %s %s' % (uw, self.matches[uw][0])

                for a, l in enumerate(self.matches[uw][0]):
                    # if uw[a] not in letters:
                    #     letters[uw[a]] = []
                    # letters[uw[a]].append(l)
                    i = ALPHABET.index(l)
                    self.crypt_alpha[l] = uw[a]

    def build_alphabet_string(self):
        # create string alphabet
        for a in self.crypt_alpha:
            self.alpha_str += self.crypt_alpha[a]
        print self.alpha_str
        print ALPHABET
        print

    """
    Iterate over matches with multiple answers and determine
    correct answer using new alphabet.
    """
    def second_pass_match(self):
        unmatched_words = []
        for uw in self.unique_words:
            if len(self.matches[uw]) > 1:
                for match in self.matches[uw]:
                    missing_letters = False

                    new_word = self.get_new_word(uw, match)

                    matched = False
                    if new_word == match:
                        matched = True

                        # this deciphered text has uncovered new letters
                        # record these to the self.crypt_alpha
                        # if new_word_2 == match:
                        #     print new_letters
                        #     for k,v in new_letters.iteritems():
                        #         self.crypt_alpha[k] = v


                    if matched:
                        self.total_matches += 1
                        print 'MATCHED: %s %s %s' % (uw, new_word, match)
                        # pass
                    else:
                        # print 'MATCHED: %s %s %s' % (uw, new_word, match)
                        # print '%s %s %s' % (uw, new_word, match)
                        # unmatched_words.append(uw)
                        pass

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
