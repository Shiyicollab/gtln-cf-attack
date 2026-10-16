"""Continued-fraction recovery for pairwise coprime GTLN private integers.

The attacker receives only the public key, b, beta, Cp and Cg. All
candidate arithmetic and coprimality checks are exact. There is no
primality test, factorization, private-key input or uncapped search.
"""
from dataclasses import dataclass, field
from fractions import Fraction
from itertools import product
from math import gcd
from time import perf_counter

@dataclass(frozen=True)
class Key:
    p: tuple
    g: int
    u: int


@dataclass
class AttackResult:
    candidates: list = field(default_factory=list)
    status: str = 'not_started'
    lo: int = -1
    hi: int = -1
    D: int = 0
    Q: int = 0
    ratios: dict = field(default_factory=dict)
    gamma_lo: int = 0
    gamma_hi: int = 0
    endpoint_scans: int = 0
    endpoint_candidates_lo: int = 0
    endpoint_candidates_hi: int = 0
    endpoint_pairs: int = 0
    integer_vectors: int = 0
    endpoint_gcd_rejections: int = 0
    reconstruction_rejections: int = 0
    coprimality_rejections: int = 0
    modulus_scans: int = 0
    modulus_upper_max: int = 0
    public_validations: int = 0
    cf_s: float = 0.0
    endpoint_s: float = 0.0
    modulus_s: float = 0.0
    elapsed_s: float = 0.0


def modulus_multiple(public, ps):
    out = 0
    for j in range(1, len(ps)):
        value = ps[0]*ps[j]*(public[0]-public[j])+ps[0]-ps[j]
        out = gcd(out, value)
    return out


def pairwise_distinct(values):
    """Comparison sorting gives a deterministic worst-case bound."""
    ordered = sorted(values)
    return all(a != b for a, b in zip(ordered, ordered[1:]))


def pairwise_coprime(values):
    """Check gcd(v_j, product of preceding values)=1, using exact integers."""
    prefix = 1
    for value in values:
        if value <= 1 or gcd(value, prefix) != 1:
            return False
        prefix *= value
    return True


def endpoint_candidates(gamma, z, P, Cp):
    lower = max(1, (gamma+P-2)//(P-1))
    upper = min(Cp, gamma//z)
    values = []
    for f in range(lower, upper+1):
        if gamma % f:
            continue
        p = gamma//f
        if z <= p < P:
            values.append(p)
    return values, max(0, upper-lower+1)


def attack(public, b, beta, Cp=2, Cg=2):
    """Return ALL candidates inside the two user-specified cofactor caps.

    The domain requires integer b,beta,Cp,Cg >= 1. Private coordinates
    may be composite, but must be pairwise coprime and lie in [2**b,
    2**(b+beta)). Return all candidates; never enlarge the given caps.
    """
    start = perf_counter()
    if not all(isinstance(x, int) for x in (b, beta, Cp, Cg)):
        raise ValueError('b, beta, Cp and Cg must be integers')
    if b < 1 or beta < 1 or Cp < 1 or Cg < 1:
        raise ValueError('Require b,beta,Cp,Cg >= 1')
    public = tuple(public)
    z, P = 1 << b, 1 << (b+beta)
    result = AttackResult()

    def finish(status):
        result.status = status
        result.elapsed_s = perf_counter()-start
        return result

    if len(public) < 3 or any(not isinstance(x, int) or x <= 0 for x in public):
        return finish('invalid_public_key')
    if not pairwise_distinct(public):
        return finish('invalid_public_key')
    lo = min(range(len(public)), key=public.__getitem__)
    hi = max(range(len(public)), key=public.__getitem__)
    D, Q = public[hi]-public[lo], 2*P**3
    result.lo, result.hi, result.D, result.Q = lo, hi, D, Q
    if z*D <= 4*Q*Q+1:
        return finish('separation_failed')
    for i, ti in enumerate(public):
        if i in (lo, hi):
            continue
        a = ti-public[lo]
        r = Fraction(a, D).limit_denominator(Q)
        N, M = r.numerator, r.denominator
        if not (0 < N < M and 2*Q*Q*abs(a*M-N*D) < D*M):
            return finish('ratio_check_failed')
        result.ratios[i] = N, M
        result.gamma_hi = gcd(result.gamma_hi, N)
        result.gamma_lo = gcd(result.gamma_lo, M-N)
    result.cf_s = perf_counter()-start
    phase = perf_counter()
    left, wleft = endpoint_candidates(result.gamma_lo, z, P, Cp)
    right, wright = endpoint_candidates(result.gamma_hi, z, P, Cp)
    result.endpoint_scans = wleft+wright
    result.endpoint_candidates_lo, result.endpoint_candidates_hi = len(left), len(right)
    result.endpoint_s = perf_counter()-phase
    for pl, ph in product(left, right):
        phase = perf_counter()
        result.endpoint_pairs += 1
        ps = None
        if gcd(pl, ph) != 1:
            result.endpoint_gcd_rejections += 1
        else:
            ps = [0]*len(public)
            ps[lo], ps[hi] = pl, ph
            for i, (N, M) in result.ratios.items():
                U = M*pl*ph
                V = ((public[i]-public[lo])*M-N*D)*pl*ph+(M-N)*ph+N*pl
                if V <= 0 or U % V:
                    ps = None
                    break
                p = U//V
                if not (z <= p < P):
                    ps = None
                    break
                ps[i] = p
            if ps is None:
                result.reconstruction_rejections += 1
            elif not pairwise_coprime(ps):
                result.coprimality_rejections += 1
                ps = None
        result.endpoint_s += perf_counter()-phase
        if ps is None:
            continue
        result.integer_vectors += 1
        phase = perf_counter()
        ps = tuple(ps)
        g0 = modulus_multiple(public, ps)
        if g0 <= 0:
            raise ArithmeticError('Pairwise-coprime fixed-anchor gcd must be positive')
        upper = min(Cg, g0//(public[hi]+1))
        result.modulus_upper_max = max(result.modulus_upper_max, upper)
        for c in range(1, upper+1):
            result.modulus_scans += 1
            if g0 % c:
                continue
            g = g0//c
            if gcd(pl, g) != 1:
                continue
            u = (pow(pl, -1, g)-public[lo]) % g
            if u == 0:
                continue
            result.public_validations += 1
            if all((p*(ti+u)-1) % g == 0 for p, ti in zip(ps, public)):
                # Different endpoint pairs or c produce different full keys.
                result.candidates.append(Key(ps, g, u))
        result.modulus_s += perf_counter()-phase
    return finish('unique' if len(result.candidates) == 1 else
                  'ambiguous' if result.candidates else 'no_candidate')
