# Smart-grid link recommendation matrix

This matrix is a qualitative engineering recommendation, not a certification.
PQC is applied first to key establishment, credentialing, firmware signing, and
other security functions that can be changed without adding work to a hard
real-time message path. Protecting each event message still requires an
authenticated, low-latency channel and a sound key lifecycle.

| Grid communication link | PQC | Hybrid classical + PQC | QKD | QRNG | Recommended posture |
|---|---|---|---|---|---|
| Control center to WAN peers | Suitable candidate for staged ML-KEM/ML-DSA pilots after interoperability and performance review | Conditional migration bridge; use a reviewed combiner/protocol, not this testbed helper | Conditional where dedicated fiber, distance, trusted nodes, and key management justify the cost | Optional entropy source subject to certification, health tests, and key-management integration | Inventory first; pilot standardized PQC at TLS/VPN/certificate boundaries and preserve cryptographic agility |
| Substation backhaul | Suitable for session establishment and device identity when the target hardware supports it | Conditional for staged transition and only with independently reviewed protocol support | Conditional niche option for fixed fiber links; not a general replacement for authenticated encryption | Optional for key generation; does not replace protocol authentication | Test key setup and rekeying off the event path; validate in the target substation and security profile |
| Substation GOOSE-like event traffic | Avoid per-event public-key operations unless the actual device/path test proves the timing budget | Avoid experimental per-event hybrid processing; consider PQC for provisioning/session establishment | Generally unsuitable as a per-event protection mechanism | Not a message-authentication mechanism | Establish keys in advance and use an approved symmetric protection profile for event traffic; validate latency, interoperability, and standard requirements |
| Meters and RTUs | Suitable candidate for onboarding, firmware verification, and key establishment when memory/CPU/firmware limits permit | Conditional; measure RAM, flash, boot time, and rekey behavior | Generally impractical for dispersed, low-cost edge endpoints | Optional only if a validated entropy source is already available | Prioritize secure update and credential lifecycle; benchmark representative hardware before selection |

## Interpretation of the measurements

The testbed compares primitive sizes and local operation times. It does not
emulate radio/fiber latency, congestion, device processors, certificate
validation chains, IEC 62351 profiles, or production link budgets. Therefore,
experimental results can flag costs and motivate pilots but cannot establish a
link's deployability or prove the red/amber/green ratings from a slide.

## Migration sequence toward 2035

1. **Inventory (now):** identify algorithms, keys, certificates, protocols,
   firmware signing, suppliers, and data retention periods.
2. **Prioritize:** rank long-lived confidentiality and safety-critical trust
   dependencies; identify harvest-now/decrypt-later exposure.
3. **Prepare:** define crypto-agility interfaces, key/certificate sizes,
   protocol interoperability tests, and hardware refresh requirements.
4. **Pilot:** test NIST-standardized ML-KEM and ML-DSA in non-critical
   authentication and key-establishment workflows with representative devices.
5. **Validate:** assess security profiles, latency, throughput, memory, key
   rotation, recovery, and vendor support before production changes.
6. **Migrate and retire:** phase by risk and asset lifetime, monitor for
   downgrade/fallback problems, and remove obsolete cryptography on a governed
   schedule.

NIST IR 8547 (final, October 2026) describes a 2035 transition timeline for
quantum-vulnerable algorithms in NIST standards, with high-risk systems
transitioning earlier. That is not a guarantee that every utility asset can be
migrated by 2035 or a universal regulatory deadline for all operators.
