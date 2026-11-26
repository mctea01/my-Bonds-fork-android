"""Measures face embedding models through the wallet's face matching pipeline on a labelled photo set.

The photo set is a directory with one subdirectory per person (the layout of LFW). Every pair of photos of
the same person is a genuine pair and every other pair an impostor pair; the report gives, per model, the
threshold for a target false accept rate and the share of genuine pairs that pass it.
"""
import argparse
import json
import os
import time

import numpy as np
from PIL import Image

from pipeline import Detector, Embedder, align


def photos(root, per_person):
    files, labels = [], []
    people = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))
    for i, person in enumerate(people):
        names = sorted(os.listdir(os.path.join(root, person)))
        if len(names) < 2:
            continue
        for name in names[:per_person]:
            files.append(os.path.join(root, person, name))
            labels.append(i)
    return files, labels


def report(genuine, impostor, thresholds):
    r = {
        "genuine": int(genuine.size), "impostor": int(impostor.size),
        "genuine_mean": float(genuine.mean()), "impostor_mean": float(impostor.mean()),
    }
    for far in (1e-3, 1e-4, 1e-5):
        t = float(np.quantile(impostor, 1 - far))
        r[f"threshold_far_{far:g}"] = round(t, 4)
        r[f"tar_far_{far:g}"] = round(float((genuine >= t).mean()), 4)
    for t in thresholds:
        r[f"far_at_{t}"] = float((impostor >= t).mean())
        r[f"tar_at_{t}"] = round(float((genuine >= t).mean()), 4)
    return r


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("photos", help="directory with one subdirectory per person")
    p.add_argument("detector", help="face_detection_short_range.tflite")
    p.add_argument("--model", action="append", required=True, metavar="NAME=PATH:NORM",
                   help="NORM is zero_one, minus_one_one or standardize; repeatable")
    p.add_argument("--per-person", type=int, default=4)
    p.add_argument("--threshold", type=float, action="append", default=[])
    p.add_argument("--out", help="write the report here as JSON")
    a = p.parse_args()

    models = {}
    for spec in a.model:
        name, rest = spec.split("=", 1)
        path, norm = rest.rsplit(":", 1)
        models[name] = Embedder(path, norm)
    detector = Detector(a.detector)
    files, labels = photos(a.photos, a.per_person)
    vectors = {name: [] for name in models}
    kept = []
    start = time.time()
    for n, (f, label) in enumerate(zip(files, labels)):
        img = Image.open(f).convert("RGB")
        points = detector.detect(img)
        if points is None:
            continue
        for name, model in models.items():
            vectors[name].append(model.embed(align(img, points, model.size)))
        kept.append(label)
        if n % 500 == 0:
            print(f"{n}/{len(files)} {time.time() - start:.0f}s", flush=True)

    labels = np.array(kept)
    upper = np.triu_indices(len(labels), 1)
    same = (labels[:, None] == labels[None, :])[upper]
    result = {"photos": int(len(labels)), "no_face": len(files) - len(kept)}
    for name in models:
        v = np.array(vectors[name])
        sim = (v @ v.T)[upper]
        result[name] = report(sim[same], sim[~same], a.threshold)
    text = json.dumps(result, indent=1)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
