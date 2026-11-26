"""Streamlit interface for local smart-grid security experiments."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from experiments.benchmarks import run_benchmarks, write_results
from security.qkd_bb84 import simulate_bb84
from security.qrng import simulated_quantum_bits
from smart_grid.simulation import run_demo_communications

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

st.set_page_config(page_title="Quantum-Safe Smart Grid Testbed", layout="wide")
st.title("Quantum-Safe Smart Grid Security Testbed")
st.caption(
    "Local software experiments only. No IEC 61850 compliance, physical quantum "
    "randomness, or production-ready security is claimed."
)

overview, measurements, qkd_tab, system_tab = st.tabs(
    ["Grid demo", "Benchmarks", "BB84 simulation", "Method and limits"]
)

with overview:
    st.subheader("Simulated communication links")
    transmissions = run_demo_communications()
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "source": item.message.source,
                    "destination": item.message.destination,
                    "link": item.message.link.value,
                    "serialized bytes": item.wire_bytes,
                    "local routing time (µs)": round(item.processing_us, 2),
                }
                for item in transmissions
            ]
        ),
        width="stretch",
        hide_index=True,
    )
    st.info("Routing time is a local serialization/replay-guard measurement, not network latency.")

with measurements:
    st.subheader("Cryptographic performance")
    iterations = st.slider("Samples per cryptographic operation", 1, 100, 25)
    if st.button("Run benchmark suite", type="primary"):
        with st.spinner("Running local crypto, BB84, QRNG, and synthetic attack demonstrations..."):
            crypto, qkd, metadata = run_benchmarks(iterations=iterations)
            write_results(crypto, qkd, metadata, RESULTS)
        st.success(f"Saved results under {RESULTS}")

    csv_path = RESULTS / "csv" / "crypto_benchmarks.csv"
    if csv_path.exists():
        crypto = pd.read_csv(csv_path)
        st.dataframe(crypto, width="stretch", hide_index=True)
        st.bar_chart(
            crypto.loc[
                crypto["operation"].isin(["sign", "verify", "encapsulate", "decapsulate"]),
                ["mechanism", "operation", "median_us"],
            ],
            x="mechanism",
            y="median_us",
            color="operation",
        )
        figure = RESULTS / "figures" / "crypto_latency.png"
        if figure.exists():
            st.image(str(figure), caption="Locally measured operation timing")
    else:
        st.info("Run the benchmark suite to produce local measurement data and figures.")

with qkd_tab:
    st.subheader("BB84 intercept-resend Monte Carlo")
    intercept = st.slider("Signals intercepted by simulated eavesdropper (%)", 0, 100, 0)
    seed = st.number_input("Reproducibility seed", min_value=0, value=6640, step=1)
    result = simulate_bb84(
        10_000,
        intercept_fraction=intercept / 100,
        seed=int(seed),
    )
    st.metric("Estimated QBER", f"{result.estimated_qber:.2%}")
    st.metric("Eavesdropper threshold exceeded", "Yes" if result.detected_eavesdropper else "No")
    st.write(
        {
            "transmitted bits": result.transmitted_bits,
            "sifted bits": result.sifted_bits,
            "sample bits": result.sample_bits,
            "remaining sifted bits (before error correction/privacy amplification)": result.remaining_sifted_bits,
            "seed": result.simulation_seed,
        }
    )
    st.warning(
        "This model is an educational Monte Carlo abstraction; it omits optical hardware, "
        "finite-key security analysis, authentication, and channel loss."
    )
    if st.button("Generate simulator measurement bits"):
        bits = simulated_quantum_bits(256, seed=int(seed))
        st.write(f"Generated {len(bits)} simulated bits; one fraction: {bits.count('1') / len(bits):.3f}")
        st.caption("Qiskit Aer uses classical simulation; these are not physical QRNG bits.")

with system_tab:
    st.subheader("Interpretation and scope")
    st.markdown(
        """
        - Cryptographic values are measured on this host and depend on processor,
          Python, library versions, and sample settings.
        - The 3 ms view is a local software-path comparison, not a GOOSE latency
          guarantee and not an IEC 61850 conformance test.
        - ML-KEM-768 and ML-DSA-65 use the installed `pqcrypto` implementation;
          this does not assert FIPS validation or a production security review.
        - The hybrid combiner is experimental and must not be used for production.
        - QKD and QRNG results are simulation outputs; QML is covered only in the
          literature review.
        """
    )
