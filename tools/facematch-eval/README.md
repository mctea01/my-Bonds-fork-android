# Face matching threshold calibration

Measures face embedding models through the same pipeline the Android wallet uses for zkPassport face
matching (Multipaz FaceNet 0.102.0 as adapted in `FacePipeline`: BlazeFace short-range, the ArcFace 4-point
alignment, the embedding model), on a public labelled photo set, and reports the match threshold for a target
false accept rate. Multipaz's default threshold of 0.63 is not calibrated (its README asks deployments to
calibrate), so the wallet's thresholds come from here.

- `pipeline.py` reimplements the Android code path.
- `evaluate.py` runs it over every photo and compares all pairs.
- `frames.py` simulates camera sessions: per-frame matching against the mean of five frames (`AveragedFaceSession`).
- `export_facenet.py` and `convert_tflite.py` make the optional FaceNet-512 model.

No photo set is kept in the repository.

## Running

Python 3.11+ with `ai-edge-litert numpy pillow`. The photo set is LFW (deep-funneled or funneled, one
directory per person), for example `lfw-funneled.tgz` from the scikit-learn download mirror
(`https://ndownloader.figshare.com/files/5976015`). The detector is Multipaz's
`multipaz-facenet/prebuilts/face_detection_short_range.tflite`.

```sh
python evaluate.py lfw_funneled face_detection_short_range.tflite \
  --model mobile=../../app/src/androidMain/assets/facenet/mobile_facenet.tflite:zero_one \
  --model facenet=../../features/facenet/src/main/assets/facenet/facenet_512.tflite:minus_one_one \
  --per-person 4 --threshold 0.47 --threshold 0.63 --threshold 0.74 --out result.json
python frames.py lfw_funneled face_detection_short_range.tflite \
  ../../app/src/androidMain/assets/facenet/mobile_facenet.tflite frames
```

`NORM` is the model's input scaling: `zero_one` (x/255, the Qualcomm MobileFaceNet), `minus_one_one`
((x-127.5)/128) or `standardize` (per-image mean and deviation).

## The FaceNet-512 model

`features/facenet/src/main/assets/facenet/facenet_512.tflite` (SHA-256
4913ec9ad500ca9c977ac1386190dae274d5bcec6d997b9589c1d55e5f3e5746) is made from facenet-pytorch's
`20180402-114759-vggface2.pt` (release v2.2.9, SHA-256
281cebca8662831adb987a874bdcb36e73f5b1c6dc5ee5878f305e985625d99b) with Python 3.11+, `torch onnx
onnx2tf tf_keras tensorflow-cpu` and `facenet-pytorch` (with torchvision, which its import needs):

```sh
python export_facenet.py 20180402-114759-vggface2.pt facenet512.onnx
onnx2tf -i facenet512.onnx -o facenet512_tf -tb tf_converter -osd
python convert_tflite.py facenet512_tf facenet_512.tflite
```

Input [1,160,160,3] float32 scaled to (x-127.5)/128, output [1,512], int8 weights (24 MB). Against PyTorch the
output has a cosine of 0.9994 (float16 weights 0.999999, at twice the size); on LFW both give the same results.

## Result (2026-11-26)

LFW funneled, people with at least two photos, at most four photos each: 4871 photos, every face found,
5312 genuine and 11,855,573 impostor pairs.

| False accept rate | MobileFaceNet | FaceNet-512, (x-127.5)/128 | FaceNet-512, standardised |
|---|---|---|---|
| 1 in 1,000 | 96.3% at 0.341 | 94.0% at 0.550 | 79.9% at 0.593 |
| 1 in 10,000 | 94.0% at 0.409 | 83.6% at 0.656 | 58.0% at 0.689 |
| 1 in 100,000 | 90.0% at 0.470 | 64.6% at 0.737 | 35.5% at 0.764 |

Each cell is the share of genuine pairs that pass, at the threshold for that false accept rate (FaceNet-512 with
int8 weights).

| MobileFaceNet threshold | False accept rate | Genuine pairs passing |
|---|---|---|
| 0.40 | 1.4 in 10,000 | 94.4% |
| 0.45 | 2.2 in 100,000 | 91.6% |
| 0.47 (the wallet) | 1.0 in 100,000 | 90.0% |
| 0.50 | 3.4 in 1,000,000 | 87.0% |
| 0.63 (Multipaz default) | 7.6 in 10,000,000 | 59.8% |

- MobileFaceNet is the better model here: it is trained on ArcFace-aligned crops, the alignment Multipaz
  applies to every camera frame. FaceNet-512 was trained on MTCNN crops with a margin, so a larger model
  does not help.
- At 0.63 four in ten genuine MobileFaceNet attempts fail. The wallet uses 0.47 for MobileFaceNet and 0.74 for
  the optional FaceNet-512, both about 1 in 100,000.
- Scores of the two models are not comparable; a threshold belongs to one model file.
- LFW is photos of the same kind; a chip portrait against a selfie, years apart, scores lower for the same
  person, while impostor scores depend little on that. A real attempt reported 0.46 against the passport.

## Camera sessions (`frames.py`)

Multipaz passes a session when two frames in a row reach the threshold, and keeps trying every frontal frame for
up to eight seconds, so someone else gets many tries. `frames.py` turns each probe photo into ten frames
(landmarks moved by about 1 pixel, brightness by up to 10%, pixel noise), compares them with another photo as
the reference, and scores a pair by its best two results in a row: per frame (Multipaz), or per mean of five
frames (the wallet). 10,624 genuine and 23,711,146 impostor ordered pairs, MobileFaceNet:

| Matching | False accepts at 0.47 | Genuine pairs passing at 0.47 |
|---|---|---|
| One photo against one photo | 1.05 in 100,000 | 89.5% |
| Ten frames, each frame | 1.24 in 100,000 | 90.5% |
| Ten frames, mean of five | 1.13 in 100,000 | 90.4% |

The simulated frames differ less than real ones and a real session has more of them, so the real gap between
the per-frame and the averaged rows is likely larger; the simulation shows the direction, not the size. Real
sessions should be measured with this tool once there is device data.
