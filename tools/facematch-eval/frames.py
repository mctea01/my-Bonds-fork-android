"""Simulates camera sessions on LFW: each probe photo becomes N jittered frames (landmark jitter, brightness,
pixel noise). Compares per-frame matching (two consecutive frames over the threshold, Multipaz) with averaging
a window of K frames (two consecutive windows over the threshold). The reference is the unjittered photo."""
import sys, json, time
import numpy as np
from PIL import Image
from pipeline import Detector, Embedder, align
from evaluate import photos

root, det_path, model_path, out = sys.argv[1:5]
N, K = 10, 5
rng = np.random.default_rng(1)
det = Detector(det_path)
emb = Embedder(model_path, "zero_one")
files, labels = photos(root, 4)
refs, probes, kept = [], [], []
t0 = time.time()
for n, (f, lab) in enumerate(zip(files, labels)):
    img = Image.open(f).convert("RGB")
    pts = det.detect(img)
    if pts is None:
        continue
    refs.append(emb.embed(align(img, pts, emb.size)))
    base = np.asarray(img, dtype=np.float32)
    fr = []
    for _ in range(N):
        p = [(x + rng.normal(0, 1.0), y + rng.normal(0, 1.0)) for x, y in pts]
        a = base * rng.uniform(0.9, 1.1) + rng.normal(0, 3.0, base.shape)
        im = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))
        fr.append(emb.embed(align(im, p, emb.size)))
    probes.append(fr)
    kept.append(lab)
    if n % 500 == 0:
        print(n, len(files), round(time.time() - t0), flush=True)
R = np.array(refs, dtype=np.float32)
P = np.array(probes, dtype=np.float32)
W = np.stack([P[:, j:j + K].sum(1) for j in range(N - K + 1)], 1)
W /= np.linalg.norm(W, axis=2, keepdims=True)
lab = np.array(kept)
np.save(out + "_R.npy", R); np.save(out + "_P.npy", P); np.save(out + "_lab.npy", lab)

def scheme(sims):
    return np.max(np.minimum(sims[..., :-1], sims[..., 1:]), -1)

gen = {"single": [], "frames": [], "window": []}
imp = {"single": [], "frames": [], "window": []}
for i0 in range(0, len(R), 400):
    r = R[i0:i0 + 400]
    s1 = r @ P[:, 0].T
    sf = scheme(np.einsum("rd,pfd->rpf", r, P))
    sw = scheme(np.einsum("rd,pfd->rpf", r, W))
    same = lab[i0:i0 + 400, None] == lab[None, :]
    self_ = np.arange(i0, i0 + len(r))[:, None] == np.arange(len(R))[None, :]
    g = same & ~self_
    im = ~same
    for k, s in (("single", s1), ("frames", sf), ("window", sw)):
        gen[k].append(s[g]); imp[k].append(s[im].astype(np.float32))
res = {"photos": len(R), "frames": N, "window": K}
for k in gen:
    g = np.concatenate(gen[k]); m = np.concatenate(imp[k])
    r = {"genuine": int(g.size), "impostor": int(m.size)}
    for far in (1e-4, 1e-5):
        t = float(np.quantile(m, 1 - far))
        r[f"thr_far_{far:g}"] = round(t, 4); r[f"tar_far_{far:g}"] = round(float((g >= t).mean()), 4)
    for t in (0.45, 0.47, 0.50):
        r[f"far_at_{t}"] = float((m >= t).mean()); r[f"tar_at_{t}"] = round(float((g >= t).mean()), 4)
    res[k] = r
print(json.dumps(res, indent=1))
open(out + ".json", "w").write(json.dumps(res, indent=1))
