"""Consolidate all URL corpora (URL1-URL4) and user feedback into a single, structured Master Binary Dataset.

File Format (master_urls.bin):
- Header (4,096 bytes):
  - Magic: b"SAFEURL1" (8 bytes)
  - Version: uint32 (1)
  - Record size: uint32 (644 bytes)
  - Total records: uint64
  - Train count: uint64
  - Val count: uint64
  - Test count: uint64
  - Feedback count: uint64
  - Feature count: uint32 (32)
  - Char length: uint32 (128)
  - Reserved padding to 4,096 bytes
- Body: Contiguous records with structured dtype:
  - features: float32[32] (128 bytes)
  - characters: int32[128] (512 bytes)
  - label: uint8 (1 byte: 0=Safe, 1=Threat)
  - split: uint8 (1 byte: 0=Train, 1=Val, 2=Test)
  - source: uint8 (1 byte: 1..4=Corpus URL1..4, 5=User Feedback)
  - reserved: uint8 (1 byte alignment)
  Total = 644 bytes per record.
"""

import os
import sys
import json
import struct
import numpy as np

HEADER_SIZE = 4096
MAGIC = b"SAFEURL1"
VERSION = 1
RECORD_SIZE = 644

URL_RECORD_DTYPE = np.dtype([
    ('features', np.float32, (32,)),
    ('characters', np.int32, (128,)),
    ('label', np.uint8),
    ('split', np.uint8),
    ('source', np.uint8),
    ('reserved', np.uint8),
])


def write_header(f, total_count, train_count, val_count, test_count, feedback_count):
    header = bytearray(HEADER_SIZE)
    # Magic (8) + Version (4) + Record Size (4)
    struct.pack_into("<8sII", header, 0, MAGIC, VERSION, RECORD_SIZE)
    # Counts: total (8), train (8), val (8), test (8), feedback (8)
    struct.pack_into("<QQQQQ", header, 16, total_count, train_count, val_count, test_count, feedback_count)
    # Dimensions: feat_dim (4), char_len (4)
    struct.pack_into("<II", header, 56, 32, 128)
    f.seek(0)
    f.write(header)


def read_header(f):
    f.seek(0)
    header = f.read(HEADER_SIZE)
    magic, version, rec_size = struct.unpack_from("<8sII", header, 0)
    if magic != MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic}")
    total_count, train_count, val_count, test_count, feedback_count = struct.unpack_from("<QQQQQ", header, 16)
    feat_dim, char_len = struct.unpack_from("<II", header, 56)
    return {
        "magic": magic.decode("ascii"),
        "version": version,
        "record_size": rec_size,
        "total_count": total_count,
        "train_count": train_count,
        "val_count": val_count,
        "test_count": test_count,
        "feedback_count": feedback_count,
        "feature_dim": feat_dim,
        "char_len": char_len
    }


def build_master_dataset(
    processed_dir: str = "data/processed/url",
    out_file: str = "data/processed/url/master_urls.bin",
    meta_out: str = "data/processed/url/master_urls_meta.json"
):
    corpora = ["URL1", "URL2", "URL3", "URL4"]
    splits = [("train", 0), ("val", 1), ("test", 2)]

    total_records = 0
    split_counts = {0: 0, 1: 0, 2: 0}
    source_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    label_counts = {0: 0, 1: 0}

    # First pass: count total records
    for c_idx, c_name in enumerate(corpora, start=1):
        meta_path = os.path.join(processed_dir, f"{c_name}_meta.json")
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Missing {meta_path}")
        with open(meta_path, "r") as mf:
            m = json.load(mf)
        for s_name, s_id in splits:
            cnt = m["counts"][s_name]
            total_records += cnt
            split_counts[s_id] += cnt

    print(f"[*] Consolidating {total_records:,} URLs across {len(corpora)} corpora...")
    print(f"    Train: {split_counts[0]:,} | Val: {split_counts[1]:,} | Test: {split_counts[2]:,}")

    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    total_bytes = HEADER_SIZE + total_records * RECORD_SIZE

    # Pre-allocate master file
    with open(out_file, "wb") as f:
        write_header(f, total_records, split_counts[0], split_counts[1], split_counts[2], 0)
        # Allocate file size
        f.seek(total_bytes - 1)
        f.write(b"\0")

    # Memory map output file for high-throughput zero-copy batch writing
    mmap_out = np.memmap(out_file, dtype=URL_RECORD_DTYPE, mode="r+", offset=HEADER_SIZE, shape=(total_records,))

    cur_idx = 0
    chunk_size = 50000

    for c_idx, c_name in enumerate(corpora, start=1):
        for s_name, s_id in splits:
            f_feat = os.path.join(processed_dir, f"{c_name}_{s_name}_feats.bin")
            f_char = os.path.join(processed_dir, f"{c_name}_{s_name}_chars.bin")
            f_lbl = os.path.join(processed_dir, f"{c_name}_{s_name}_labels.bin")

            with open(os.path.join(processed_dir, f"{c_name}_meta.json"), "r") as mf:
                sub_count = json.load(mf)["counts"][s_name]

            # Read source arrays with memmap
            src_feats = np.memmap(f_feat, dtype=np.float32, mode="r", shape=(sub_count, 32))
            src_chars = np.memmap(f_char, dtype=np.int32, mode="r", shape=(sub_count, 128))
            src_labels = np.memmap(f_lbl, dtype=np.int32, mode="r", shape=(sub_count,))

            for offset in range(0, sub_count, chunk_size):
                end = min(offset + chunk_size, sub_count)
                n_items = end - offset
                dest_slice = slice(cur_idx, cur_idx + n_items)

                mmap_out['features'][dest_slice] = src_feats[offset:end]
                mmap_out['characters'][dest_slice] = src_chars[offset:end]
                lbl_chunk = src_labels[offset:end].astype(np.uint8)
                mmap_out['label'][dest_slice] = lbl_chunk
                mmap_out['split'][dest_slice] = s_id
                mmap_out['source'][dest_slice] = c_idx
                mmap_out['reserved'][dest_slice] = 0

                cur_idx += n_items
                source_counts[c_idx] += n_items
                label_counts[0] += int(np.sum(lbl_chunk == 0))
                label_counts[1] += int(np.sum(lbl_chunk == 1))

            print(f"  [+] Merged {c_name} {s_name} ({sub_count:,} records)")

    mmap_out.flush()
    del mmap_out

    meta = {
        "master_file": out_file,
        "total_records": total_records,
        "header_size": HEADER_SIZE,
        "record_size": RECORD_SIZE,
        "split_counts": {
            "train": split_counts[0],
            "val": split_counts[1],
            "test": split_counts[2]
        },
        "label_counts": {
            "safe": label_counts[0],
            "threat": label_counts[1]
        },
        "corpora": corpora
    }
    with open(meta_out, "w") as mf:
        json.dump(meta, mf, indent=2)

    file_size_mb = os.path.getsize(out_file) / (1024 * 1024)
    print(f"\n[*] Master URL Dataset successfully built at {out_file} ({file_size_mb:.2f} MB)")
    print(f"    Total: {total_records:,} URLs ({label_counts[0]:,} Safe, {label_counts[1]:,} Threats)")
    return meta


if __name__ == "__main__":
    build_master_dataset()
