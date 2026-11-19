"""Efficient Binary Dataset Loader for URL Threat Training."""

import os
import json
import numpy as np
import torch
from torch.utils.data import Dataset


class BinaryUrlDataset(Dataset):
    """Memory-mapped binary dataset for URL features, characters, and labels."""

    def __init__(self, prefix: str, split: str = "train"):
        self.feat_file = f"{prefix}_{split}_feats.bin"
        self.char_file = f"{prefix}_{split}_chars.bin"
        self.label_file = f"{prefix}_{split}_labels.bin"
        meta_file = f"{prefix}_meta.json"

        if not os.path.exists(meta_file):
            raise FileNotFoundError(f"Metadata file not found: {meta_file}")

        with open(meta_file, "r") as f:
            self.meta = json.load(f)

        self.count = self.meta["counts"][split]
        self.feat_dim = self.meta.get("featureCount", 32)
        self.char_len = self.meta.get("charLength", 128)

        # Memory map arrays for zero-copy high-throughput access
        self.features = np.memmap(self.feat_file, dtype=np.float32, mode="r", shape=(self.count, self.feat_dim))
        self.characters = np.memmap(self.char_file, dtype=np.int32, mode="r", shape=(self.count, self.char_len))
        self.labels = np.memmap(self.label_file, dtype=np.int32, mode="r", shape=(self.count,))

    def __len__(self) -> int:
        return self.count

    def __getitem__(self, idx: int):
        feat = torch.from_numpy(self.features[idx].copy())
        char = torch.from_numpy(self.characters[idx].copy())
        label = int(self.labels[idx])
        return feat, char, label

