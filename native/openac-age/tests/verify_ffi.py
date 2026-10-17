#!/usr/bin/env python3
"""Check the actual generated UniFFI C ABI using a retained synthetic Rust proof."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


def prove_through_ffi(native, assets, fixture, parent):
    with tempfile.TemporaryDirectory(prefix="synthetic-ffi-", dir=parent) as temporary:
        documents = Path(temporary) / "circom"
        for source in assets.rglob("*"):
            if not source.is_file():
                continue
            target = documents / source.relative_to(assets)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(source, target)
            except OSError:
                shutil.copyfile(source, target)
        path = str(documents)
        prepared = native.create_age_prepare_input(path, fixture["sd_jwt"],
            fixture["issuer_x"], fixture["issuer_y"])
        prepare = native.prove_jwt(path, native.ZkCancelToken())
        native.create_age_show_input(path, fixture["nonce"], fixture["device_signature"],
            prepared.claim_name, prepared.claim_format, fixture["cutoff"])
        show = native.prove_show(path, native.ZkCancelToken())
        native.generate_shared_blinds(path, native.ZkCancelToken())
        native.reblind_jwt(path, native.ZkCancelToken())
        native.reblind_show(path, native.ZkCancelToken())
        assert native.verify_age_presentation(path, fixture["nonce"], prepared.claim_name,
            prepared.claim_format, fixture["cutoff"], fixture["issuer_x"], fixture["issuer_y"], native.ZkCancelToken())
        signals = native.read_public_signals(path, native.ZkCancelToken())
        assert len(signals.prepare) == 6 and len(signals.show) == 156
        print("UniFFI full proof: prepare_ms=%d show_ms=%d prepare_bytes=%d show_bytes=%d" %
            (prepare.total_ms, show.total_ms, prepare.proof_size_bytes, show.proof_size_bytes))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bindings", type=Path)
    parser.add_argument("documents", type=Path)
    parser.add_argument("--assets", type=Path, help="Also prove through every generated UniFFI operation")
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
    if args.assets:
        prove_through_ffi(native, args.assets.resolve(), fixture, args.documents.resolve().parent)


if __name__ == "__main__":
    main()
