"""Converts the onnx2tf SavedModel of FaceNet-512 to TFLite with int8 dynamic-range weights and float32 input
and output (the file in app/src/androidMain/assets/facenet). onnx2tf's own float16 file has float16 input and
output, which Multipaz's interpreter does not feed."""
import argparse

import tensorflow as tf


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("saved_model", help="directory written by onnx2tf -osd")
    p.add_argument("out", help="TFLite file to write")
    p.add_argument("--float16", action="store_true", help="float16 weights instead of int8 (twice the size)")
    a = p.parse_args()
    c = tf.lite.TFLiteConverter.from_saved_model(a.saved_model)
    c.optimizations = [tf.lite.Optimize.DEFAULT]
    if a.float16:
        c.target_spec.supported_types = [tf.float16]
    with open(a.out, "wb") as f:
        f.write(c.convert())


if __name__ == "__main__":
    main()
