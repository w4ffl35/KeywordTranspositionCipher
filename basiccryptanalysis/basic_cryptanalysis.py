#!/usr/bin/env python
import os
from keywordtranspositioncipher.keyword_transposition_cipher import KeywordTranspositionCipher
import collections


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
expected_answers = [
    'skulker', 'choke', 'minifloppies', 'scratched', 'recursions', 'hairiest',
    'boas', 'dps', 'twiddles', 'orthogonal', 'posers', 'stoppage', 'echo',
    'cranking', 'roached', 'trawling', 'saying', 'confusers', 'sysop', 'bytes',
    'punting', 'minifloppieses', 'patch', 'ruder', 'pop', 'urchin', 'zaps',
    'lase', 'post', 'bit', 'incantation', 'barns', 'munches', 'trawl',
    'newsgroups', 'wins', 'scrogs', 'gnarliest', 'arena', 'losses',
    'compressing', 'funkiest', 'musics', 'fences', 'wanked', 'drivers',
    'weasel', 'dinker', 'phases', 'nuke', 'driver', 'globed', 'biffed', 'slops',
    'patches', 'deltas', 'bombed', 'bouncing', 'cripplewares', 'dec', 'tubes',
    'grunge', 'pasties', 'trashing', 'hats', 'whacking', 'hairballs', 'pmed',
    'drone', 'fools', 'urls', 'pushing', 'twiddle', 'phage', 'screen',
    'segmented', 'foregrounded', 'spoiler', 'profiles', 'blts', 'bounced',
    'tourists', 'clean', 'clobbers', 'pods', 'gobble', 'con', 'cubings',
    'snailing', 'download', 'rfcs', 'hose', 'widget', 'compacter', 'adas',
    'glitched', 'crumb', 'mailbombs', 'snark'
]
# expected_answers = ['ilove', 'solvi', 'ngpro', 'gramm', 'ingch', 'allen', 'ges']
# expected_answers = ['crypt', 'ology']
class BasicCryptanalysis(object):
    def __init__(self):
        self.PASS = 0
        self.results = collections.OrderedDict()
        self.used_keys = []

        # prepare secrets
        #raw_input().upper()
        self.prepare_secrets()

        # prepare answers
        self.prepared_answers = [a.upper() for a in expected_answers]

        # prepare dictionary
        with open(os.path.join(HERE, 'dictionary.lst')) as f:
            lines = f.readlines()
        self.prepared_dictionary = [l.upper().strip() for l in lines]

    def prepare_secrets(self):
        secrets = "lhpohes gvjhe ztytwojmmtel lgsfcgver segpsltjyl vftstelc djfl rml catrroel jscvjqjyfo mjlesl lcjmmfqe egvj gsfyhtyq sjfgver csfaotyq lfxtyq gjywplesl lxljm dxcel mpyctyq ztytwojmmtelel mfcgv spres mjm psgvty bfml ofle mjlc dtc tygfycfctjy dfsyl zpygvel csfao yealqsjpml atyl lgsjql qyfsotelc fseyf ojllel gjzmselltyq wpyhtelc zpltgl weygel afyher rstnesl aefleo rtyhes mvflel yphe rstnes qojder dtwwer lojml mfcgvel reocfl djzder djpygtyq gstmmoeafsel reg cpdel qspyqe mflctel csflvtyq vfcl avfghtyq vftsdfool mzer rsjye wjjol psol mplvtyq catrroe mvfqe lgseey leqzeycer wjseqsjpyrer lmjtoes msjwtoel docl djpyger cjpstlcl goefy gojddesl mjrl qjddoe gjy gpdtyql lyftotyq rjayojfr swgl vjle atrqec gjzmfgces frfl qotcgver gspzd zftodjzdl lyfsh"
        # secrets = 'LDXTW KXDTL NBSFX BFOII LNBHG ODDWN BWK'
        secrets = secrets.upper().strip()
        self.prepared_secrets = []
        self.prepared_secrets.append(secrets.split(' '))


    def run(self):
        running = True
        new_prepared_dict = self.prepared_dictionary
        newk = ''
        pairs = []
        used_crypts = []
        self.used_alpha = []

        # On each subsequent run, append a matching crypt from the previous pass
        # to each key in the prepared dictionary.
        while running:
            # track the number of passes we have made
            self.PASS += 1
            print 'PASS: %s' % self.PASS

            # each pass assumes it is the last
            running = False

            # set the dictionary to use
            # starts with self.prepared_dictionary, continues with dictionary
            # created with uncovered keys.
            prepared_dictionary = new_prepared_dict
            for key in prepared_dictionary:
                pairs, used_crypts, running = self.decrypt(key, pairs, used_crypts, running)

                # for alpha in self.used_alpha:
                #     for k in used_crypts:
                #         pairs, used_crypts, running = self.decrypt(k+key, pairs, used_crypts, running, alpha)

    def decrypt(self, key, pairs, used_crypts, running, alpha=None):
        # run a keyword transposition cipher
        lines = sum(
            KeywordTranspositionCipher.run([key], self.prepared_secrets, alpha),
            []
        )

        # if we have a match, do some things
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
                        # create a new dictionary
                        if crypt not in self.prepared_dictionary:
                            used_crypts.append(crypt)

                        # track the results
                        self.used_keys.append(key)
                        self.results[crypt].append(l)
                        self.used_alpha.append(KeywordTranspositionCipher.NEW_ALPHA)

                        # print the match
                        print "%s %s %s" % (
                            crypt,
                            l,
                            key
                        )
                        print ':)'

                        # do another pass
                        running = True
        return pairs, used_crypts, running
