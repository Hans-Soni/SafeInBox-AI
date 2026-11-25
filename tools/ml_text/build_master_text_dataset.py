"""Consolidate all Email/Text corpora (text1-text4, both) and user feedback into a single, structured Master Binary Dataset.

File Format (master_emails.bin):
- Header (4,096 bytes):
  - Magic: b"SAFETXT1" (8 bytes)
  - Version: uint32 (1)
  - Record size: uint32 (1028 bytes)
  - Total records: uint64
  - Train count: uint64
  - Val count: uint64
  - Test count: uint64
  - Feedback count: uint64
  - Sequence length: uint32 (128)
  - Vocab size: uint32 (16384)
  - Reserved padding to 4,096 bytes
- Body: Contiguous records with structured dtype:
  - input_ids: int32[128] (512 bytes)
  - attention_mask: int32[128] (512 bytes)
  - label: uint8 (1 byte: 0=Safe, 1=Threat)
  - split: uint8 (1 byte: 0=Train, 1=Val, 2=Test)
  - source: uint8 (1 byte: 1..5=Corpus text1..both, 6=User Feedback)
  - reserved: uint8 (1 byte alignment)
  Total = 1,028 bytes per record.
"""

import os
import sys
import json
import struct
import numpy as np

HEADER_SIZE = 4096
MAGIC = b"SAFETXT1"
VERSION = 1
RECORD_SIZE = 1028
SEQ_LEN = 128
VOCAB_SIZE = 16384

TEXT_RECORD_DTYPE = np.dtype([
    ('input_ids', np.int32, (128,)),
    ('attention_mask', np.int32, (128,)),
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
    # Dimensions: seq_len (4), vocab_size (4)
    struct.pack_into("<II", header, 56, SEQ_LEN, VOCAB_SIZE)
    f.seek(0)
    f.write(header)


def read_header(f):
    f.seek(0)
    header = f.read(HEADER_SIZE)
    magic, version, rec_size = struct.unpack_from("<8sII", header, 0)
    if magic != MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic}")
    total_count, train_count, val_count, test_count, feedback_count = struct.unpack_from("<QQQQQ", header, 16)
    seq_len, vocab_size = struct.unpack_from("<II", header, 56)
    return {
        "magic": magic.decode("ascii"),
        "version": version,
        "record_size": rec_size,
        "total_count": total_count,
        "train_count": train_count,
        "val_count": val_count,
        "test_count": test_count,
        "feedback_count": feedback_count,
        "seq_len": seq_len,
        "vocab_size": vocab_size
    }


def build_master_dataset(
    processed_dir: str = "data/processed/text",
    out_file: str = "data/processed/text/master_emails.bin",
    meta_out: str = "data/processed/text/master_emails_meta.json"
):
    corpora = [
        ("text1", 1),
        ("text2", 2),
        ("text3", 3),
        ("text4", 4),
        ("both", 5)
    ]
    splits = [("train", 0), ("val", 1), ("test", 2)]

    total_records = 0
    split_counts = {0: 0, 1: 0, 2: 0}
    source_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0}
    label_counts = {0: 0, 1: 0}

    # First pass: count total records
    for c_name, c_id in corpora:
        meta_path = os.path.join(processed_dir, f"{c_name}_meta.json")
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Missing {meta_path}")
        with open(meta_path, "r") as mf:
            m = json.load(mf)
        for s_name, s_id in splits:
            cnt = m["counts"][s_name]
            total_records += cnt
            split_counts[s_id] += cnt

    print(f"[*] Consolidating {total_records:,} Email texts across {len(corpora)} corpora...")
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
    mmap_out = np.memmap(out_file, dtype=TEXT_RECORD_DTYPE, mode="r+", offset=HEADER_SIZE, shape=(total_records,))

    cur_idx = 0
    chunk_size = 20000

    for c_name, c_id in corpora:
        for s_name, s_id in splits:
            f_ids = os.path.join(processed_dir, f"{c_name}_{s_name}_input_ids.bin")
            f_mask = os.path.join(processed_dir, f"{c_name}_{s_name}_attention_mask.bin")
            f_lbl = os.path.join(processed_dir, f"{c_name}_{s_name}_labels.bin")

            with open(os.path.join(processed_dir, f"{c_name}_meta.json"), "r") as mf:
                sub_count = json.load(mf)["counts"][s_name]

            # Read source arrays with memmap
            src_ids = np.memmap(f_ids, dtype=np.int32, mode="r", shape=(sub_count, SEQ_LEN))
            src_mask = np.memmap(f_mask, dtype=np.int32, mode="r", shape=(sub_count, SEQ_LEN))
            src_labels = np.memmap(f_lbl, dtype=np.int32, mode="r", shape=(sub_count,))

            for offset in range(0, sub_count, chunk_size):
                end = min(offset + chunk_size, sub_count)
                n_items = end - offset
                dest_slice = slice(cur_idx, cur_idx + n_items)

                mmap_out['input_ids'][dest_slice] = src_ids[offset:end]
                mmap_out['attention_mask'][dest_slice] = src_mask[offset:end]
                lbl_chunk = src_labels[offset:end].astype(np.uint8)
                mmap_out['label'][dest_slice] = lbl_chunk
                mmap_out['split'][dest_slice] = s_id
                mmap_out['source'][dest_slice] = c_id
                mmap_out['reserved'][dest_slice] = 0

                cur_idx += n_items
                source_counts[c_id] += n_items
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
        "corpora": [c[0] for c in corpora]
    }
    with open(meta_out, "w") as mf:
        json.dump(meta, mf, indent=2)

    file_size_mb = os.path.getsize(out_file) / (1024 * 1024)
    print(f"\n[*] Master Email Dataset successfully built at {out_file} ({file_size_mb:.2f} MB)")
    print(f"    Total: {total_records:,} Emails ({label_counts[0]:,} Safe, {label_counts[1]:,} Threats)")
    return meta


if __name__ == "__main__":
    build_master_dataset()
