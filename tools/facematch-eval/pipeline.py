"""The face matching pipeline of Multipaz FaceNet 0.102.0 (multipaz-facenet), as the wallet runs it on Android.

BlazeFace short-range finds the face and its landmarks on a 128x128 letterboxed copy (AndroidFaceDetector,
BlazeFaceDecoder), a similarity transform maps the eyes, nose tip and mouth centre onto the ArcFace 112x112
template scaled to the model's input (computeFaceAlignmentTransform), and the embedding model runs on that
crop (AndroidFaceNetInterpreter). Embeddings are L2-normalised, so their dot product is the cosine similarity.
"""
import math
import numpy as np
from PIL import Image
from ai_edge_litert.interpreter import Interpreter

INPUT = 128

def anchors():
    strides = [8, 16, 16, 16]
    mn, mx = 0.1484375, 0.75
    out = []
    layer = 0
    while layer < len(strides):
        count = 0
        last = layer
        while last < len(strides) and strides[last] == strides[layer]:
            count += 2
            last += 1
        fm = math.ceil(INPUT / strides[layer])
        for y in range(fm):
            for x in range(fm):
                for _ in range(count):
                    out.append(((x + 0.5) / fm, (y + 0.5) / fm))
        layer = last
    return np.array(out, dtype=np.float32)

ANCHORS = anchors()

class Detector:
    def __init__(self, path):
        self.it = Interpreter(model_path=path, num_threads=4)
        self.it.allocate_tensors()
        outs = self.it.get_output_details()
        self.reg = 0 if outs[0]["shape"][-1] == 16 else 1
        self.cls = 1 - self.reg
        self.outs = outs

    def detect(self, img):
        w, h = img.size
        scale = INPUT / max(w, h)
        dw, dh = max(1, int(w * scale)), max(1, int(h * scale))
        dx, dy = (INPUT - dw) // 2, (INPUT - dh) // 2
        canvas = Image.new("RGB", (INPUT, INPUT))
        canvas.paste(img.resize((dw, dh), Image.BILINEAR), (dx, dy))
        x = (np.asarray(canvas, dtype=np.float32) - 127.5) / 127.5
        self.it.set_tensor(self.it.get_input_details()[0]["index"], x[None])
        self.it.invoke()
        boxes = self.it.get_tensor(self.outs[self.reg]["index"])[0]
        scores = self.it.get_tensor(self.outs[self.cls]["index"])[0][:, 0]
        s = 1 / (1 + np.exp(-np.clip(scores, -100, 100)))
        padx = (INPUT - w * scale) / 2
        pady = (INPUT - h * scale) / 2
        best = None
        for i in np.where(s >= 0.6)[0]:
            if best is None or s[i] > s[best]:
                best = i
        if best is None:
            return None
        ax, ay = ANCHORS[best]
        b = boxes[best]
        def pt(k):
            nx = b[4 + 2 * k] / INPUT + ax
            ny = b[5 + 2 * k] / INPUT + ay
            return ((nx * INPUT - padx) / scale, (ny * INPUT - pady) / scale)
        return [pt(0), pt(1), pt(2), pt(3)]

TEMPLATE = [(0.341916, 0.461574), (0.656534, 0.459834), (0.500225, 0.640505), (0.501246, 0.823971)]

def align(img, pts, size):
    src = np.array(pts, dtype=np.float64)
    dst = np.array(TEMPLATE, dtype=np.float64) * size
    ms, md = src.mean(0), dst.mean(0)
    s0, d0 = src - ms, dst - md
    var = (s0 ** 2).sum()
    a = (s0[:, 0] * d0[:, 0] + s0[:, 1] * d0[:, 1]).sum() / var
    b = (s0[:, 0] * d0[:, 1] - s0[:, 1] * d0[:, 0]).sum() / var
    tx = md[0] - (a * ms[0] - b * ms[1])
    ty = md[1] - (b * ms[0] + a * ms[1])
    # dst = [[a,-b],[b,a]] src + t; PIL wants the inverse (dst -> src).
    det = a * a + b * b
    ia, ib = a / det, -b / det
    inv = (ia, -ib, -(ia * tx - ib * ty), ib, ia, -(ib * tx + ia * ty))
    return img.transform((size, size), Image.AFFINE, inv, resample=Image.BILINEAR)

class Embedder:
    def __init__(self, path, norm):
        self.it = Interpreter(model_path=path, num_threads=4)
        self.it.allocate_tensors()
        ins = self.it.get_input_details()
        d = ins[0]
        self.indexes = [i["index"] for i in ins]
        shape = d["shape"]
        self.first = shape[1] == 3
        self.size = shape[2] if self.first else shape[1]
        self.out = self.it.get_output_details()[0]["index"]
        self.norm = norm

    def embed(self, face):
        x = np.asarray(face, dtype=np.float32)
        if self.norm == "zero_one":
            x = x / 255.0
        elif self.norm == "minus_one_one":
            x = (x - 127.5) / 128.0
        else:
            x = (x - x.mean()) / max(x.std(), 1 / math.sqrt(x.size))
        if self.first:
            x = x.transpose(2, 0, 1)
        for i in self.indexes:
            self.it.set_tensor(i, x[None].astype(np.float32))
        self.it.invoke()
        e = self.it.get_tensor(self.out)[0].astype(np.float64)
        return e / np.linalg.norm(e)
