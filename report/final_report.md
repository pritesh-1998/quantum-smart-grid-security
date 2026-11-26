# Quantum-Based Security Solutions for Smart Grids

**Course:** INSE 6640  
**Group:** Group 6  
**Project status:** Software experiment and literature comparison  
**Benchmark run:** 25 primitive-operation samples; 500 local-message trials; 256-byte payload  
**Execution environment:** Python 3.12.16, macOS 26.6.2 arm64 (10 logical CPUs) (see `results/metadata.json`)

## Abstract

This project builds a reproducible, local software testbed to compare classical
and post-quantum cryptographic primitives for representative smart-grid
communication roles. It implements X25519 key agreement, RSA-2048 and ECDSA
signatures, AES-256-GCM, HMAC-SHA-256, NIST ML-KEM-768 and ML-DSA-65, an
experimental X25519/ML-KEM combiner, a Monte Carlo BB84 model, and a Qiskit Aer
measurement demonstration. The benchmark records local execution time and
encoded sizes, while integrity and replay demonstrations use synthetic
messages. The outputs are educational measurements, not certification,
IEC 61850 validation, or evidence of physical quantum security.

## 1. Problem and research questions

Smart-grid security dependencies may outlive individual device and protocol
lifetimes. Public-key algorithms based on factoring and discrete logarithms
are vulnerable to a sufficiently capable quantum computer, while grid links
also have varied timing, bandwidth, and endpoint constraints.

- **RQ1:** Where do smart-grid communication systems depend on
  quantum-vulnerable cryptography?
- **RQ2:** How do classical and post-quantum mechanisms compare in local
  latency and encoded size, and what can that comparison say about tight
  message paths?
- **RQ3:** What staged migration approach is appropriate for different
  communication links?

## 2. Scope and threat model

The simulated roles are a control center, substation, RTU, and smart meter.
Messages represent control-center/WAN, substation GOOSE-like event, and AMI
traffic. The adversary can observe, modify, inject, or replay messages in the
conceptual model. A future quantum computer is considered a threat to
quantum-vulnerable public-key mechanisms.

The testbed does not connect to a real utility network, implement IEC 61850 or
IEC 62351, model power-system physics, or test a live attack. The defensive
attack demonstrations check only synthetic AES-GCM tampering, signature
tampering, and duplicate message identifiers. Endpoint compromise, denial of
service, side channels, key-management infrastructure, and network impairment
are outside scope.

## 3. Method

### 3.1 Implemented mechanisms

| Family | Implementation |
|---|---|
| Classical key establishment | X25519 with HKDF-SHA-256 |
| Classical signatures | RSA-2048/PSS and ECDSA P-256 |
| Symmetric protection | AES-256-GCM and HMAC-SHA-256 |
| PQ key establishment | ML-KEM-768 via `pqcrypto` |
| PQ signatures | ML-DSA-65 via `pqcrypto` |
| Experimental hybrid | X25519 + ML-KEM-768 concatenated-secret HKDF combiner |
| QKD | Seeded Monte Carlo BB84 and intercept-resend model |
| QRNG | Qiskit Aer measurement demonstration |
| Quantum ML | Literature discussion only |

FIPS 203/204 standardize the ML-KEM and ML-DSA algorithm families. The selected
Python library is not claimed to be FIPS validated. The hybrid combiner is a
teaching experiment, not a standardized protocol or reviewed production design.
The NIST FIPS 203/204 publication pages list potential errata/update notes as
of this report's 2026-11-18 review date; implementations should check the
current errata.

### 3.2 Measurements

Each cryptographic timing is measured in this Python process using
`perf_counter_ns`, summarized as median and empirical 95th percentile. The
default run uses 25 samples per primitive operation and a 256-byte payload.
Public-key, ciphertext, signature, and payload lengths are recorded separately.
The substation timing path combines local serialization, AES-GCM, HMAC, and an
in-memory route. Its 3 ms percentage excludes real network and field-device
effects and must not be interpreted as GOOSE conformance.

BB84 results use 10,000 seeded Monte Carlo signal transmissions for each
interception level. QRNG bit balance comes from a seeded simulator. Re-run
settings and host details are saved in `results/metadata.json`.

### 3.3 Reproducibility

```bash
.venv/bin/python -m pytest
.venv/bin/python -m experiments.run_benchmarks --iterations 25 --timing-trials 500
.venv/bin/streamlit run dashboard/app.py
```

The benchmark writes `results/csv/crypto_benchmarks.csv`,
`results/csv/qkd_experiment.csv`, `results/metadata.json`, and figures under
`results/figures/`. Measurements in those files are host-dependent.

## 4. Results

The benchmark was executed on the host named in the run metadata. Values are
host- and library-version-dependent.

### 4.1 Primitive timing

| Mechanism / operation | Median (µs) | P95 (µs) |
|---|---:|---:|
| X25519 key generation | 27.125 | 34.875 |
| X25519 two-party session establishment | 87.334 | 111.167 |
| X25519 session-key derivation only | 32.125 | 32.667 |
| RSA-2048 key generation | 44,422.500 | 107,977.625 |
| RSA-2048 signing / verification | 599.416 / 32.625 | 615.084 / 42.291 |
| ECDSA P-256 signing / verification | 24.125 / 75.750 | 25.875 / 85.791 |
| ML-KEM-768 key generation | 45.375 | 53.833 |
| ML-KEM-768 encapsulation / decapsulation | 53.666 / 66.167 | 61.750 / 68.792 |
| ML-DSA-65 key generation | 192.834 | 198.917 |
| ML-DSA-65 signing / verification | 6,703.625 / 132.250 | 6,806.209 / 139.875 |
| Experimental X25519 + ML-KEM two-party establishment | 312.375 | 373.625 |
| AES-256-GCM encrypt / decrypt | 3.375 / 1.834 | 9.542 / 3.125 |
| HMAC-SHA-256 authenticate and verify | 3.041 | 6.167 |

### 4.2 Encoded size

| Mechanism / encoding | Public key (bytes) | Ciphertext (bytes) | Signature / tag (bytes) |
|---|---:|---:|---:|
| X25519 public key | 32 | — | — |
| RSA-2048 (DER public key) | 294 | — | 256 |
| ECDSA P-256 (DER public key) | 91 | — | 70 in this sample |
| ML-KEM-768 | 1,184 | 1,088 | — |
| ML-DSA-65 | 1,952 | — | 3,309 |
| AES-256-GCM, 256-byte payload | — | 284 including nonce and tag | — |

ECDSA signatures use a variable-length DER encoding; 70 bytes is the observed
encoding in this run, not a fixed size. The RSA public-key number is Subject
Public Key Info DER encoding.

### 4.3 BB84 and message timing

| Scenario | Measurement |
|---|---|
| No simulated interception | QBER 0.00%; 3,977 sifted bits remain after sampling, before error correction/privacy amplification |
| 25% intercept-resend | Estimated QBER 8.02%; below the selected 11% threshold |
| Full intercept-resend | Estimated QBER 24.88%; toy protocol aborts |
| Local authenticated-message path | Median 20.584 µs, P95 22.083 µs; 500/500 under 3 ms |
| Simulated QRNG output | 4,096 bits; ones fraction 0.5007 |

The two-party X25519 timing includes key generation at both endpoints and
derivation; the hybrid timing includes the analogous X25519 keys, ML-KEM key
generation, encapsulation, decapsulation, and derivation in this implementation.
The BB84 estimates vary with the seeded sample and parameter-estimation sample
size. The sub-11% estimate at 25% interception is not a claim that such
interception is safe; it illustrates that estimated QBER is noisy and
thresholded. The count remaining after sampling is not a final secret key:
error correction, privacy amplification, authentication, and finite-key
analysis are not implemented. The BB84 results are simulated and the timing
figure is local to the test host.

## 5. Discussion and recommendation

PQC is most directly useful for replacing vulnerable key establishment and
signatures where the protocol and device support the new encodings. Real-time
message protection should separate key establishment from the event path: use
pre-established symmetric keys with a standards-appropriate authenticated
protection mechanism rather than assume that a PQ signature should be added to
every event message.

QKD may be considered for selected fixed links when dedicated optical
infrastructure, distance, trusted-node design, authentication, and key
management justify the operational cost. It does not replace endpoint
authentication, symmetric encryption, or migration of public-key
authentication. QRNG can be an optional entropy component only after validation
of a physical source and integration. QML remains outside the implementation.
NIST IR 8547's final October 2026 transition timeline uses 2035 for removing
quantum-vulnerable algorithms from NIST standards, with high-risk systems
transitioning sooner. It is not a universal regulatory deadline for utilities.

The link-level comparison and migration actions are documented in
`research/recommendation_matrix.md`. A deployment decision requires
representative field devices, applicable IEC security profiles, and
vendor/interoperability testing.

### Research-question answers

- **RQ1:** The experiment demonstrates exposure classes rather than auditing an
  actual utility. Public-key key establishment and signatures in TLS/VPN,
  certificate, firmware-signing, and device-identity workflows are candidates
  for inventory. The project did not inspect deployed grid equipment, so it
  cannot identify which algorithms are installed at a specific utility.
- **RQ2:** In this run, ML-DSA-65 signing took 6,703.625 µs median for a
  256-byte message and produced a 3,309-byte signature. That local signature
  operation alone exceeded the project-selected 3 ms comparison threshold,
  while the local AES-GCM/HMAC message path was 20.584 µs median. These are
  single-host Python measurements; they do not prove a PQ signature is
  unsuitable on all devices or that the symmetric path meets any field
  deadline.
- **RQ3:** Use the link-specific matrix: pilot standardized PQC for key
  establishment and identity workflows, keep public-key work off a
  time-critical event path until representative devices and profiles are
  validated, and treat QKD/QRNG as infrastructure-specific options.

## 6. Limitations

1. This is a single-host software experiment, not a network emulation or
   hardware benchmark.
2. It does not implement IEC 61850 or IEC 62351.
3. The 3 ms value is a comparison threshold selected for the project, not a
   universal standard limit. The local path excludes real networks,
   operating-system scheduling, and field devices.
4. The PQC library is not claimed to be certified or FIPS validated.
5. The hybrid combiner is experimental and unaudited.
6. BB84 omits optical channels, finite-key security, device imperfections,
   authenticated post-processing, and link budgets.
7. Qiskit Aer output is simulated, seeded pseudo-randomness, not a physical
   QRNG.
8. The attack checks are local functional tests, not penetration testing.
9. No statistical confidence analysis across multiple hosts or actual grid
   equipment is included.

## 7. Conclusion

The testbed makes the cost trade-offs of selected classical and standardized
post-quantum primitives measurable and repeatable, and demonstrates why
link-specific migration matters. It supports a staged, crypto-agile PQC
assessment, with quantum technologies treated as conditional options rather
than universal replacements. Final suitability depends on the applicable
standards, actual equipment, system-level timing, and a formal security
assessment.

## References

1. NIST, [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), 2024.
2. NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final), 2024.
3. NIST, [Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography).
4. NIST, [IR 8547: Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/final), October 2026.
5. IEC Editorial Team, [Cyber security: understanding IEC 62351](https://www.iec.ch/blog/cyber-security-understanding-iec-62351), January 23, 2023.
6. C. H. Bennett and G. Brassard, “Quantum cryptography: Public key distribution and coin tossing,” *Proceedings of IEEE International Conference on Computers, Systems and Signal Processing*, Bangalore, 1984, pp. 175–179; reprinted in *Theoretical Computer Science* 560 (2014), pp. 7–11, [doi:10.1016/j.tcs.2014.05.025](https://doi.org/10.1016/j.tcs.2014.05.025).
7. NIST, [SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation](https://csrc.nist.gov/pubs/sp/800/90/b/final), 2018.
8. NIST, [SP 800-90A Rev. 1: Recommendation for Random Number Generation Using Deterministic Random Bit Generators](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), 2015.
9. H. M. Ngo, T. R. Jeter, J. T. Seo, and M. T. Thai, “QUPID: A Partitioned Quantum Neural Network for Anomaly Detection in Smart Grid,” *IEEE Transactions on Smart Grid*, published June 19, 2026, [doi:10.1109/TSG.2026.3705645](https://doi.org/10.1109/TSG.2026.3705645). Not evaluated or reproduced in this project.
