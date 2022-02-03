from pycipher import SimpleSubstitution
from breaking.substitution import SubstitutionBreak

from util.transforms import Masker
from score.ioc import IocScorer
from data.en import load_ngrams
from score.ngram import NgramScorer

def break_substitution_example(plaintext, masker):
    print("#############################################")
    print("######## Substitution cipher example ########")
    print("#############################################")

    key = ['L', 'C', 'N', 'D', 'T', 'H', 'E', 'W', 'Z', 'S', 'A', 'R', 'X',
           'V', 'O', 'J', 'B', 'P', 'F', 'U', 'I', 'Q', 'M', 'K', 'G', 'Y']
    ciphertext = SimpleSubstitution(key).encipher(plaintext)

    print("\nCiphertext:\n---")
    print(masker.extend(ciphertext))
    print("---\n")

    print("\nCracking...\n")
    scorer = NgramScorer(load_ngrams(4))
    breaker = SubstitutionBreak(scorer, seed=42)
    breaker.optimise(ciphertext, n=3)
    decryption, score, key = breaker.guess(ciphertext)[0]
    print("Substitution decryption (key={}, score={}):\n---\n{}---\n"
          .format(key, score, masker.extend(decryption)))


if __name__ == "__main__":
    with open("examples/text.txt", "r") as f:
        plaintext, masker = Masker.from_text(f.read())

    break_substitution_example(plaintext, masker)
