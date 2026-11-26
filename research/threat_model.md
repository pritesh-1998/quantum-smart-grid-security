# Scope and threat model

## System under study

This project models four logical node roles: control center, substation, remote
terminal unit (RTU), and smart meter. It models three message classes: control
center/WAN, substation event (GOOSE-like), and meter/AMI. The simulator routes
JSON messages inside one Python process. It does not implement a real power
system, IEC 61850 stack, or network transport.

## Assets

- Integrity and authenticity of control commands and telemetry.
- Confidentiality of selected meter and operational information.
- Long-lived signing and key-establishment credentials.
- Availability and timeliness of simulated messages.
- Evidence needed to inventory cryptographic dependencies and plan migration.

## Trust boundaries and adversary

The model considers a remote network adversary who can observe, alter, replay,
or inject messages, and a future cryptographically relevant quantum computer
that threatens widely deployed public-key schemes based on factoring or
discrete logarithms. A compromised endpoint or stolen private key is also a
relevant operational risk but is not simulated.

The local demonstrations cover AES-GCM tampering, signature tampering, and
duplicate message identifiers. They do not model traffic interception,
production key management, routing, denial of service, side channels, device
compromise, or exploitation of a live utility network.

## Security assumptions and limitations

- AES-GCM and HMAC-SHA-256 are baseline symmetric mechanisms; correct key
  lifecycle, nonce handling, authentication, and endpoint protection remain
  necessary.
- ML-KEM-768 and ML-DSA-65 are the algorithm names from NIST FIPS 203/204.
  Using a library that implements them is not equivalent to FIPS validation,
  certification, or an operational security assessment.
- The X25519 + ML-KEM combiner in this testbed is experimental. It is not a
  standardized hybrid protocol and has not received a formal cryptographic
  proof or review.
- BB84 uses a seeded Monte Carlo model, not optical components, an authenticated
  classical channel, finite-key analysis, or a full QKD security proof.
- The QRNG demo measures simulated qubits in Qiskit Aer. Its seed and simulator
  are classical; it is not physical quantum entropy.
- The 3 ms threshold is a project comparison target, not a universal IEC 61850
  service requirement. A local Python result cannot establish compliance.

## Defensive validation plan

1. Verify confidentiality and integrity with authenticated-encryption round
   trips and tamper rejection.
2. Verify classical and post-quantum signatures against modified messages.
3. Check KEM encapsulation/decapsulation agreement and hybrid combiner
   agreement.
4. Demonstrate duplicate-ID rejection in the in-memory simulation.
5. Compare controlled BB84 runs with no interception and intercept-resend.
6. Measure operations locally and retain runtime, configuration, and raw CSV
   data with the generated figures.

## Standards to consult

- [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST IR 8547: Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/final)
- [IEC: Cyber security and IEC 62351](https://www.iec.ch/blog/cyber-security-understanding-iec-62351)
- [Bennett and Brassard, 1984, BB84 (2014 reprint)](https://doi.org/10.1016/j.tcs.2014.05.025)

The standards and papers inform the discussion; this software does not claim
conformance to them.
