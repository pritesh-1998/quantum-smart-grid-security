# Literature review: quantum-safe smart-grid security

## Question and scope

The study asks which quantum-safe mechanisms are plausible for different
smart-grid communication links, considering cryptographic strength, latency,
message-size overhead, endpoint constraints, and deployment architecture. The
work compares standardized post-quantum cryptographic (PQC) primitives with
classical baselines and treats QKD and quantum-randomness claims as separate
physical-system questions.

## Post-quantum cryptography

NIST finalized ML-KEM in FIPS 203 and ML-DSA in FIPS 204 in 2024. ML-KEM is a
key-encapsulation mechanism; it is not bulk encryption or a signature. ML-DSA
is a signature scheme. These distinctions matter in a grid design: a KEM
establishes a shared secret, while a symmetric authenticated-encryption
mechanism protects messages after key establishment.

The experiment uses ML-KEM-768 and ML-DSA-65 through the `pqcrypto` Python
package. The testbed measures primitive operations and encodings; it neither
claims that the package is a validated cryptographic module nor estimates
production protocol performance. NIST's PQC project and migration guidance
should be consulted alongside the final standards before procurement or
deployment decisions.

NIST IR 8547, finalized in October 2026, describes a transition timeline in
which quantum-vulnerable algorithms are deprecated and ultimately removed from
NIST standards by 2035, with high-risk systems transitioning earlier. This is
the basis for using 2035 as a planning horizon here; it does not mean every
utility asset is guaranteed or legally required to migrate by that date.
As of November 18, 2026, the FIPS 203 and FIPS 204 landing pages also list
potential errata/update notes. Implementers should check current errata before
relying on a particular implementation.

## Smart-grid timing and protocol context

Power automation has distinct traffic profiles: event traffic may have tight
delivery requirements, while control-center/backhaul and meter workflows have
different bandwidth and device constraints. A local cryptographic microbenchmark
does not include a communication channel, operating-system scheduling,
protection-system processing, or device-specific implementations. The
3-millisecond benchmark in this project is therefore a deliberately labeled
comparison threshold, not a claim that all GOOSE traffic has that deadline or
that a measured percentage proves conformance.

IEC 62351 provides security standards for power-system communications. A
production design must select the applicable parts and profiles for its
protocols, devices, and operational requirements; this Python model does not
implement or test those profiles.

## QKD and BB84

BB84 is a quantum key-distribution protocol based on non-orthogonal quantum
states and authenticated classical post-processing. An intercept-resend
demonstration can illustrate that measurements in a mismatched basis induce
errors. It does not reproduce the end-to-end security proof, finite-key
effects, detector imperfections, source flaws, authentication requirements,
fiber attenuation, trusted-node exposure, or operational key-management
integration. QKD is an infrastructure choice for specific links, not a
drop-in replacement for public-key cryptography or authenticated encryption.

The project uses a Monte Carlo BB84 abstraction to compare a clean channel with
intercept-resend scenarios. The QBER output is simulated and must not be
presented as a field measurement.

## QRNG and quantum machine learning

The QRNG demonstration prepares simulated qubits in superposition and samples
Qiskit Aer measurements. Since the simulator is classical and seeded, it
demonstrates circuit workflow only; it does not demonstrate a quantum entropy
source. NIST SP 800-90B addresses entropy-source design and validation for
random-bit generators; this project does not implement such validation.
Physical random-number generators require a documented entropy source, health
tests, and appropriate validation.

Quantum machine learning is not implemented. A 2026 IEEE Transactions on Smart
Grid article proposes a partitioned quantum neural network for smart-grid
anomaly detection and reports results for detection and robustness scenarios.
This is a research direction, not independently validated evidence of
production advantage: this project does not reproduce the paper, its datasets,
or its baselines. QML evaluation would require controlled conventional
detectors, representative datasets, threat models, and hardware-aware
resource measurements.

## References

1. NIST, [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), 2024.
2. NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final), 2024.
3. NIST, [Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography).
4. NIST, [IR 8547: Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/final), October 2026.
5. IEC Editorial Team, [Cyber security: understanding IEC 62351](https://www.iec.ch/blog/cyber-security-understanding-iec-62351), January 23, 2023.
6. C. H. Bennett and G. Brassard, “Quantum cryptography: Public key distribution and coin tossing,” *Proceedings of IEEE International Conference on Computers, Systems and Signal Processing*, Bangalore, 1984, pp. 175–179; reprinted in *Theoretical Computer Science* 560 (2014), pp. 7–11, [doi:10.1016/j.tcs.2014.05.025](https://doi.org/10.1016/j.tcs.2014.05.025).
7. NIST, [SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation](https://csrc.nist.gov/pubs/sp/800/90/b/final), 2018. It includes entropy-source requirements and validation tests.
8. NIST, [SP 800-90A Rev. 1: Recommendation for Random Number Generation Using Deterministic Random Bit Generators](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), 2015. This is a deterministic-RBG reference, not a QRNG validation.
9. H. M. Ngo, T. R. Jeter, J. T. Seo, and M. T. Thai, “QUPID: A Partitioned Quantum Neural Network for Anomaly Detection in Smart Grid,” *IEEE Transactions on Smart Grid*, published June 19, 2026, [doi:10.1109/TSG.2026.3705645](https://doi.org/10.1109/TSG.2026.3705645). Cited as a research direction only; the reported results were not reproduced here.
