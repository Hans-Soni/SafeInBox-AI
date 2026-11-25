"""Efficient Master Binary Dataset Loader for Email/Text Threat Training.

Supports:
1. MasterTextDataset: Zero-copy memory-mapped access to master_emails.bin.
2. FastMasterTextBatchLoader: Ultra-fast vectorized batch slicing directly from disk in O(1) time.
3. BinaryTextDataset: Maintained for legacy compatibility with individual corpus splits.
"""

import os
import json
import struct
import numpy as np
import torch
from torch.utils.data import Dataset

HEADER_SIZE = 4096
MAGIC = b"SAFETXT1"
RECORD_SIZE = 1028
SEQ_LEN = 128

TEXT_RECORD_DTYPE = np.dtype([
    ('input_ids', np.int32, (128,)),
    ('attention_mask', np.int32, (128,)),
    ('label', np.uint8),
    ('split', np.uint8),
    ('source', np.uint8),
    ('reserved', np.uint8),
])


class MasterTextDataset(Dataset):
    """Memory-mapped dataset reading directly from the consolidated master_emails.bin file."""

    def __init__(self, bin_path: str = "data/processed/text/master_emails.bin", split: str = "train"):
        if not os.path.exists(bin_path):
            raise FileNotFoundError(f"Master Email dataset not found at {bin_path}")

        self.bin_path = bin_path
        self.split_name = split
        split_map = {"train": 0, "val": 1, "test": 2}
        if split not in split_map:
            raise ValueError(f"Invalid split: {split}. Expected one of {list(split_map.keys())}")
        self.split_id = split_map[split]

        # Read header metadata
        with open(bin_path, "rb") as f:
            header_bytes = f.read(HEADER_SIZE)
            magic, version, rec_size = struct.unpack_from("<8sII", header_bytes, 0)
            if magic != MAGIC:
                raise ValueError(f"Invalid magic bytes in {bin_path}: {magic}")
            total_count, train_count, val_count, test_count, feedback_count = struct.unpack_from("<QQQQQ", header_bytes, 16)
            self.total_records = total_count
            self.counts = {"train": train_count, "val": val_count, "test": test_count, "feedback": feedback_count}

        # Memory-map the contiguous records
        self.mmap = np.memmap(
            self.bin_path,
            dtype=TEXT_RECORD_DTYPE,
            mode="r",
            offset=HEADER_SIZE,
            shape=(self.total_records,)
        )

        # Pre-index indices belonging to this split for O(1) lookup
        all_splits = self.mmap['split']
        self.indices = np.where(all_splits == self.split_id)[0]
        self.count = len(self.indices)

        # Fast label access
        self.labels = self.mmap['label'][self.indices]

    def __len__(self) -> int:
        return self.count

    def __getitem__(self, idx: int):
        global_idx = self.indices[idx]
        rec = self.mmap[global_idx]
        ids = torch.from_numpy(rec['input_ids'].copy()).long()
        mask = torch.from_numpy(rec['attention_mask'].copy()).long()
        label = int(rec['label'])
        return ids, mask, label

    def get_batch(self, batch_sub_indices):
        """Vectorized batch slice: fetches a full batch in a single C-level memory copy."""
        global_indices = self.indices[batch_sub_indices]
        recs = self.mmap[global_indices]
        ids = torch.from_numpy(recs['input_ids'].copy()).long()
        mask = torch.from_numpy(recs['attention_mask'].copy()).long()
        labels = torch.from_numpy(recs['label'].copy()).long()
        return ids, mask, labels


class FastMasterTextBatchLoader:
    """High-throughput vectorized batch generator bypassing PyTorch per-item DataLoader overhead."""

    def __init__(self, dataset: MasterTextDataset, batch_size: int = 512, shuffle: bool = True):
        self.dataset = dataset
        self.batch_size = batch_size
        self.shuffle = shuffle
        self.num_samples = len(dataset)
        self.num_batches = (self.num_samples + batch_size - 1) // batch_size

    def __len__(self) -> int:
        return self.num_batches

    def __iter__(self):
        if self.shuffle:
            perm = np.random.permutation(self.num_samples)
        else:
            perm = np.arange(self.num_samples)

        for i in range(0, self.num_samples, self.batch_size):
            batch_perm = perm[i : i + self.batch_size]
            yield self.dataset.get_batch(batch_perm)


class BinaryTextDataset(Dataset):
    """Memory-mapped binary dataset for tokenized input_ids, attention_mask, and labels (legacy individual corpora)."""

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
