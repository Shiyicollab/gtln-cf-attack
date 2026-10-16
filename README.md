# GTLN Key Recovery via Continued Fractions

Python implementation of a continued-fraction key-recovery attack on the
Gomez-Torrecillas--Lobillo--Navarro (GTLN) cryptosystem.

The attack supports **pairwise coprime private integers**. It does not require
the private integers to be prime and performs no primality tests. The supplied
experiments generate prime private coordinates for the **24 parameter sets
recommended in the original cryptosystem paper**.

## Requirements

- Python 3.10 or later; Python 3.12 is recommended for reproducing the experiments.
- Python standard library only. No additional packages are required.

Download this repository using **Code > Download ZIP**, extract it, and open
a terminal in the directory containing `benchmark.py`.
On Windows, `py -3` may be used in place of `python` in the commands below.

## Quick start

Run two trials for each of three representative parameter sets:

```bash
python benchmark.py --sets 1,17,24 --trials 2 --Cp 2 --Cg 2 --seed 20261012 --out quick_run
```

Run the complete experiment: 24 parameter sets, 100 keys per set:

```bash
python benchmark.py --trials 100 --Cp 2 --Cg 2 --seed 20261012 --out results_rerun
```

Use a fresh output directory for each run. The program refuses to overwrite
an existing experiment. `--sets` accepts comma-separated set numbers from
1 to 24, or `all`. `--trials` specifies the number of keys per set.

## Recover a key from public data only

```bash
python attack_public.py results/public_set_01.json --Cp 2 --Cg 2 --out recovered.json
```

Input JSON contains `b`, `beta`, and `public`. Public-key integers are stored
as decimal strings to avoid loss of precision in other JSON readers.
The output contains the recovery status and all candidate private keys;
large output integers are also represented as decimal strings.

## Files

| File | Purpose |
| --- | --- |
| `cf_attack.py` | Continued-fraction attack, bounded candidate search, coprimality and public-equation checks |
| `key_generation.py` | The 24 recommended parameter sets and reproducible prime-based key generation |
| `benchmark.py` | Runs the experiments and checks recovery after the attack timer stops |
| `attack_public.py` | Recovers candidates from a public-key JSON file |
| `README_使用说明.txt` | Detailed Chinese instructions and an explanation of the algorithm |
| `RESULTS.txt` | Summary and per-parameter results of the supplied experiment |
| `RESULT_COLUMNS.txt` | Explanation of result columns |
| `results/` | Raw trials, summaries, environment metadata and example public keys |
| `SHA256SUMS.txt` | Checksums of the accompanying files |

## Included experimental results

The supplied experiment used `Cp = Cg = 2`, seed `20261012`, and 100 trials
per parameter set, for a total of **2,400 trials**. Every trial returned
exactly one candidate, equal to the original private key.

The mean complete attack time was **14.283 ms** on an Intel Core i7-14700
running Windows 11 and CPython 3.12.14. Attack timing includes public-input
checks, continued fractions, candidate enumeration, coprimality checks,
modulus search, and public-equation verification. It excludes key generation,
ground-truth evaluation and file I/O.

The raw data are in `results/raw_trials.csv`; per-set summaries are in
`results/summary.csv` and `results/summary.json`. Runtime depends on hardware
and system load. A fixed seed and the same Python version reproduce the
public-key samples and mathematical results, not identical timings.

## Recovery conditions and experimental scope

The attacker receives the public key, `b`, `beta`, `Cp` and `Cg`. It does not
receive the original private key or the plaintext-weight parameter `t`.
The search caps are fixed: the algorithm does not increase them automatically.

The algorithm returns every candidate passing its public checks within the
chosen caps. There may be no candidate, one candidate, or multiple candidates.
Inclusion of the original private key requires the separation condition
and the three true cofactors to lie within their corresponding bounds.

All supplied benchmark keys use prime private coordinates. No recovery
experiment on composite private coordinates is included. These experiments
do not establish a cofactor distribution for arbitrary composite keys or
empirically verify a failure probability as small as 2^-80.

The prime-generation backend is restricted to `b + beta <= 78`; all 24
recommended parameter sets satisfy this restriction. The public-key attack
has no restriction arising from this primality backend.
