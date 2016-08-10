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
    def __init__(self):
        self.PASS = 0
        self.results = collections.OrderedDict()
        self.used_keys = []
        self.prepare_secrets()
        self.prepare_answers()
        self.prepare_dictionary()
        self.frequency_analysis()
        self.letter_roughness = 0.0

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

    def frequency_analysis(self):
        unique_letter_count = 0
        total_letter_count = 0
        letter_data = {}

        for l in ALPHABET:
            letter_data[l] = Letter(l)

        for secrets in self.prepared_secrets:
            for word in secrets:
                for letter in word:
                    if letter_data[letter].total_count == 0:
                        unique_letter_count += 1
                    letter_data[letter].total_count += 1
                    total_letter_count += 1

        self.set_letter_roughness(letter_data, unique_letter_count, total_letter_count)

    def set_letter_roughness(self, letter_data, unique_letter_count, total_letter_count):
        # lower number == easier cipher
        alpha_letter_count = len(ALPHABET)

        avg_letter_distribution = total_letter_count / unique_letter_count
        above_avg_letters = 0
        for k,l in letter_data.items():
            if l.total_count >= avg_letter_distribution:
                above_avg_letters += 1

        self.letter_roughness = above_avg_letters / alpha_letter_count

    def determine_longest_word(self, words):
        longest_word = ''
        longest_word_len = 0
        for word in words:
            if len(word) > longest_word_len:
                longest_word_len = len(word)
                longest_word = word
        return longest_word

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
        self.used_alpha = []

        used_words = []
        matches = collections.OrderedDict()

        for i, secret in enumerate(self.prepared_secrets[0]):
            for answer in self.prepared_dictionary:
                if len(secret) == len(answer):
                    same_word = float(0)
                    # check frequency of letters in above words
                    uniq_letters_crypt = []
                    uniq_letters_plaintext = []
                    n = 1 / len(secret)
                    for i, l in enumerate(secret):
                        if secret[i] not in uniq_letters_crypt:
                            uniq_letters_crypt.append(secret[i])

                        if answer[i] not in uniq_letters_plaintext:
                            uniq_letters_plaintext.append(answer[i])

                        freq_crypt = self.get_letter_frequency_in_word(secret, secret[i])
                        freq_plaintext = self.get_letter_frequency_in_word(answer, answer[i])

                        if freq_crypt == freq_plaintext:
                            same_word += n

                    y = round(same_word, 2)
                    if y >= 0.99:
                        if secret not in matches.keys():
                            matches[secret] = []
                        matches[secret].append(answer)
                        used_words.append(secret)

        unique_words = list(set(used_words))
        letters = {}
        alpha = collections.OrderedDict()
        for n in ALPHABET:
            alpha[n] = ' '
        for uw in unique_words:
            if len(matches[uw]) == 1:
                print 'MATCH: %s %s' % (uw, matches[uw][0])

                for a, l in enumerate(matches[uw][0]):
                    if uw[a] not in letters:
                        letters[uw[a]] = []
                    letters[uw[a]].append(l)
                    i = ALPHABET.index(l)
                    alpha[l] = uw[a]
        alpha_str = ''
        for a in alpha:
            alpha_str += alpha[a]
        print alpha_str
        print ALPHABET



    def decipher(self, key, pairs, new_prepared_dict, running, alpha=None):
        lines = KeywordTranspositionCipher.run(
            [key], self.prepared_secrets, alpha
        )

        old_prepared_dict = list(new_prepared_dict)
        new_prepared_dict = []

        if bool(set(lines) & set(self.prepared_answers)):
            for l in lines:
                if l in self.prepared_answers:
                    i = lines.index(l)
                    crypt = self.prepared_secrets[0][i]

                    if crypt not in self.results.keys():
                        self.results[crypt] = []

                    p = (key, crypt, l)
                    if p not in pairs:
                        pairs.append(p)
                        if crypt not in new_prepared_dict and crypt not in old_prepared_dict:
                            new_prepared_dict.append(crypt)

                        # track the results
                        self.used_keys.append(key)
                        self.results[crypt].append(l)
                        self.used_alpha.append(KeywordTranspositionCipher.NEW_ALPHA)

                        # print the match
                        print "%s %s %s" % (
                            crypt, l, key
                        )
                        print ':)'

                        # do another pass
                        running = True
        return pairs, new_prepared_dict, running
