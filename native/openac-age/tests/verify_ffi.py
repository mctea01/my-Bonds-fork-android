#!/usr/bin/env python3
"""Check the actual generated UniFFI C ABI using a retained synthetic Rust proof."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bindings", type=Path)
    parser.add_argument("documents", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("diw_zk", args.bindings / "diw_zk.py")
    native = importlib.util.module_from_spec(spec)
    sys.modules["diw_zk"] = native
    spec.loader.exec_module(native)
    documents = str(args.documents.resolve())
    fixture = json.loads((args.documents / "synthetic-fixture.json").read_text())
    assert "openac" in native.native_info().features
    assert native.self_test()
    prepared = native.create_age_prepare_input(str(args.documents / "synthetic-input"),
        fixture["sd_jwt"], fixture["issuer_x"], fixture["issuer_y"])
    assert prepared.claim_name == "birthdate" and prepared.claim_format == 2
    token = native.ZkCancelToken()
    token.cancel()
    try:
        native.prove_jwt(documents, token)
        raise AssertionError("Cancelled proof unexpectedly started")
    except native.ZkError.Cancelled:
        pass
    signals = native.read_public_signals(documents, native.ZkCancelToken())
    assert len(signals.prepare) == 6 and len(signals.show) == 156
    for delta, expected in [(0, True), (1, False)]:
        accepted = native.verify_age_presentation(documents, fixture["nonce"], fixture["claim_name"],
            fixture["claim_format"], fixture["cutoff"] + delta, fixture["issuer_x"], fixture["issuer_y"], native.ZkCancelToken())
        assert accepted is expected
    print("UniFFI OpenAC: native self-test, synthetic input, cancellation, signals and age policy passed")


if __name__ == "__main__":
    main()
