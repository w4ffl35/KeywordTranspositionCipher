#!/usr/bin/env python
import os
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(HERE, "..", "."))
from basiccryptanalysis.basic_cryptanalysis import BasicCryptanalysis


class BasicCryptanalysisChallengeTest(unittest.TestCase):
    def test_sample_input_outputs_dictionary_words(self):
        input_text = "lhpohes gvjhe ztytwojmmtel lgsfcgver segpsltjyl vftstelc djfl rml catrroel jscvjqjyfo mjlesl lcjmmfqe egvj gsfyhtyq sjfgver csfaotyq lfxtyq gjywplesl lxljm dxcel mpyctyq ztytwojmmtelel mfcgv spres mjm psgvty bfml ofle mjlc dtc tygfycfctjy dfsyl zpygvel csfao yealqsjpml atyl lgsjql qyfsotelc fseyf ojllel gjzmselltyq wpyhtelc zpltgl weygel afyher rstnesl aefleo rtyhes mvflel yphe rstnes qojder dtwwer lojml mfcgvel reocfl djzder djpygtyq gstmmoeafsel reg cpdel qspyqe mflctel csflvtyq vfcl avfghtyq vftsdfool mzer rsjye wjjol psol mplvtyq catrroe mvfqe lgseey leqzeycer wjseqsjpyrer lmjtoes msjwtoel docl djpyger cjpstlcl goefy gojddesl mjrl qjddoe gjy gpdtyql lyftotyq rjayojfr swgl vjle atrqec gjzmfgces frfl qotcgver gspzd zftodjzdl lyfsh"

        bc = BasicCryptanalysis(secrets=input_text)
        result = bc.execute()

        # Ensure result is a string and lowercase
        self.assertIsInstance(result, str)
        self.assertEqual(result, result.lower())

        # Validate every returned word is in the dictionary file
        dict_words = set([w.lower() for w in bc.prepared_dictionary])
        output_words = [w for w in result.split() if w]
        self.assertEqual(len(output_words), len(input_text.split()))
        for w in output_words:
            self.assertIn(w, dict_words)


if __name__ == "__main__":
    unittest.main()
