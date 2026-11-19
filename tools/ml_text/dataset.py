"""Zero-copy memory-mapped binary dataset for email text threat training."""

import os
import json
import numpy as np
import torch
from torch.utils.data import Dataset


class BinaryTextDataset(Dataset):
    """Memory-mapped binary dataset for tokenized input_ids, attention_mask, and labels."""

    def __init__(self, prefix: str, split: str = "train"):
        self.ids_file = f"{prefix}_{split}_input_ids.bin"
        self.mask_file = f"{prefix}_{split}_attention_mask.bin"
        self.label_file = f"{prefix}_{split}_labels.bin"
        meta_file = f"{prefix}_meta.json"

        if not os.path.exists(meta_file):
            raise FileNotFoundError(f"Metadata file not found: {meta_file}")

        with open(meta_file, "r") as f:
            self.meta = json.load(f)

        self.count = self.meta["counts"][split]
        self.seq_len = self.meta.get("seqLength", 128)

        # Memory map arrays for zero-copy high-throughput access
        self.input_ids = np.memmap(self.ids_file, dtype=np.int32, mode="r", shape=(self.count, self.seq_len))
        self.attention_mask = np.memmap(self.mask_file, dtype=np.int32, mode="r", shape=(self.count, self.seq_len))
        self.labels = np.memmap(self.label_file, dtype=np.int32, mode="r", shape=(self.count,))

    def __len__(self) -> int:
        return self.count

    def __getitem__(self, idx: int):
        input_ids = torch.from_numpy(self.input_ids[idx].copy()).long()
        attention_mask = torch.from_numpy(self.attention_mask[idx].copy()).long()
        label = int(self.labels[idx])
        return input_ids, attention_mask, label

