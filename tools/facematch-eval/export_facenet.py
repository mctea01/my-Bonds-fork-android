"""Exports facenet-pytorch's InceptionResnetV1 (VGGFace2 weights, a port of David Sandberg's 20180402-114759,
MIT) to ONNX, for the comparison in README.md. Convert the ONNX file with onnx2tf, then to TFLite."""
import argparse

import torch
from facenet_pytorch.models.inception_resnet_v1 import InceptionResnetV1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("weights", help="20180402-114759-vggface2.pt from the facenet-pytorch v2.2.9 release")
    p.add_argument("out", help="ONNX file to write")
    a = p.parse_args()
    model = InceptionResnetV1(pretrained=None, classify=False)
    state = {k: v for k, v in torch.load(a.weights, map_location="cpu").items() if not k.startswith("logits")}
    model.load_state_dict(state)
    model.eval()
    torch.onnx.export(model, torch.randn(1, 3, 160, 160), a.out, input_names=["input"],
                      output_names=["embedding"], opset_version=17, dynamo=False)


if __name__ == "__main__":
    main()
