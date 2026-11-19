"""Export PyTorch Checkpoint to Browser ONNX Model."""

import os
import torch
import onnx
from model import HybridUrlThreatNet

device = torch.device("cpu")
model = HybridUrlThreatNet(feature_dim=32, char_seq_len=128, vocab_size=135).to(device)

import sys

checkpoint_path = sys.argv[1] if len(sys.argv) > 1 else "data/models/url_unified.pt"
export_path = sys.argv[2] if len(sys.argv) > 2 else "extension/models/url-threat.onnx"

print(f"[*] Loading checkpoint from: {checkpoint_path}")
checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
model.load_state_dict(checkpoint["model_state_dict"])
model.eval()
os.makedirs(os.path.dirname(export_path), exist_ok=True)

dummy_feats = torch.randn(1, 32, dtype=torch.float32, device=device)
dummy_chars = torch.randint(0, 100, (1, 128), dtype=torch.int32, device=device)

torch.onnx.export(
    model,
    (dummy_feats, dummy_chars),
    export_path,
    export_params=True,
    opset_version=14,
    do_constant_folding=True,
    dynamo=False,
    input_names=["features", "characters"],
    output_names=["output"],
    dynamic_axes={
        "features": {0: "batch_size"},
        "characters": {0: "batch_size"},
        "output": {0: "batch_size"}
    }
)

onnx_model = onnx.load(export_path)
onnx.checker.check_model(onnx_model)
size_mb = os.path.getsize(export_path) / (1024 * 1024)
print(f"[*] ONNX model successfully verified and exported to {export_path} ({size_mb:.2f} MB)")

