"""Run all reproducible measurements and write result artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from experiments.benchmarks import run_benchmarks, write_results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--payload-bytes", type=int, default=256)
    parser.add_argument("--timing-trials", type=int, default=500)
    parser.add_argument("--output", type=Path, default=Path("results"))
    args = parser.parse_args()

    crypto, qkd, metadata = run_benchmarks(
        iterations=args.iterations,
        payload_bytes=args.payload_bytes,
        timing_trials=args.timing_trials,
    )
    write_results(crypto, qkd, metadata, args.output)
    print(f"Wrote {len(crypto)} cryptographic measurements to {args.output / 'csv'}")
    print(f"Wrote {len(qkd)} BB84 scenarios to {args.output / 'csv'}")
    print(crypto[["mechanism", "operation", "median_us", "p95_us"]].to_string(index=False))
    print(qkd[["intercept_fraction", "estimated_qber", "detected_eavesdropper"]].to_string(index=False))


if __name__ == "__main__":
    main()
