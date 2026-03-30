"""ML-KEM parameter sets.

These values follow the standard Kyber/ML-KEM parameter families and are used
as input to scaffolded scheme functions.
"""

ML_KEM_512 = {
    "name": "ML-KEM-512",
    "q": 3329,
    "n": 256,
    "k": 2,
    "eta1": 3,
    "eta2": 2,
    "du": 10,
    "dv": 4,
}

ML_KEM_768 = {
    "name": "ML-KEM-768",
    "q": 3329,
    "n": 256,
    "k": 3,
    "eta1": 2,
    "eta2": 2,
    "du": 10,
    "dv": 4,
}

ML_KEM_1024 = {
    "name": "ML-KEM-1024",
    "q": 3329,
    "n": 256,
    "k": 4,
    "eta1": 2,
    "eta2": 2,
    "du": 11,
    "dv": 5,
}

ML_KEM_PARAM_SETS = {
    "ML-KEM-512": ML_KEM_512,
    "ML-KEM-768": ML_KEM_768,
    "ML-KEM-1024": ML_KEM_1024,
    "512": ML_KEM_512,
    "768": ML_KEM_768,
    "1024": ML_KEM_1024,
}

__all__ = [
    "ML_KEM_512",
    "ML_KEM_768",
    "ML_KEM_1024",
    "ML_KEM_PARAM_SETS",
]
