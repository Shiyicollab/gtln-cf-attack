"""Prime-based key generation for the 24 recommended GTLN parameter sets.

This module belongs to the experiment, not to the public-key attack.
The twelve-base primality decision is exact below PRIME_LIMIT.
"""
from dataclasses import dataclass
import hashlib
import json
from math import isqrt
import random
from cf_attack import Key

PRIME_LIMIT = 318665857834031151167461
MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
SMALL_PRIMES = tuple(p for p in range(2, 300)
                     if all(p % q for q in range(2, isqrt(p)+1)))


def is_prime(x):
    """Exact below PRIME_LIMIT (Sorenson--Webster); never trial-divide to sqrt(x)."""
    if x >= PRIME_LIMIT:
        raise ValueError('Exact primality backend requires x < PRIME_LIMIT')
    if x < 2:
        return False
    for p in SMALL_PRIMES:
        if x % p == 0:
            return x == p
    d, s = x-1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in MR_BASES:
        y = pow(a, d, x)
        if y == 1 or y == x-1:
            continue
        for _ in range(s-1):
            y = y*y % x
            if y == x-1:
                break
        else:
            return False
    return True


@dataclass(frozen=True)
class Params:
    n: int
    t: int
    b: int
    beta: int

    @property
    def z(self): return 1 << self.b

    @property
    def P(self): return 1 << (self.b+self.beta)

    @property
    def G(self):
        d = self.b+self.beta
        return 2*max(self.b+(self.t-1).bit_length()+(self.t-1)*d, self.t*d)+3


PARAMETERS = tuple(Params(*p) for p in [
    (85,22,60,1),(90,23,60,1),(90,26,50,15),(95,22,70,1),
    (95,25,55,1),(100,20,50,1),(100,25,55,1),(110,25,60,1),
    (110,30,40,20),(125,20,60,1),(125,25,40,1),(150,20,40,5),
    (150,30,30,20),(150,30,50,1),(175,30,45,1),(175,40,30,20),
    (200,40,70,1),(200,50,45,10),(225,45,45,5),(225,55,40,10),
    (250,60,50,1),(250,55,30,20),(300,60,50,1),(400,50,50,1)
])


def make_rng(seed, set_id, trial):
    data = json.dumps(['gtln-coprime', seed, set_id, trial], separators=(',', ':'))
    return random.Random(int.from_bytes(hashlib.sha256(data.encode()).digest(), 'big'))


def keygen(par, rng):
    """Uniform integer -> next prime, uniform G-bit coprime g, valid uniform u."""
    if par.b < 1 or par.beta < 1 or par.b+par.beta > 78:
        raise ValueError('Prime-generation backend requires 1 <= b,beta and b+beta <= 78')
    ps, seen = [], set()
    while len(ps) < par.n:
        p = rng.randrange(par.z, par.P)+1
        if p % 2 == 0:
            p += 1
        while p < par.P and not is_prime(p):
            p += 2
        if p < par.P and p not in seen:
            ps.append(p)
            seen.add(p)
    while True:
        g = (1 << (par.G-1)) | rng.getrandbits(par.G-1)
        if all(g % p for p in ps):
            break
    hs = [pow(p, -1, g) for p in ps]
    forbidden = set(hs)
    while True:
        u = rng.randrange(1, g)
        if u not in forbidden:
            break
    return tuple((h-u) % g for h in hs), Key(tuple(ps), g, u)


