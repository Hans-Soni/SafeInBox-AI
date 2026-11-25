"""Ultra-Fast Master Email Text Model Training using Vectorized Memory-Mapped Slicing.

Implements:
1. MasterTextDataset & FastMasterTextBatchLoader: Zero-copy C-level array slicing from master_emails.bin.
2. TextThreatNet: Multi-scale n-gram convolutions (k=2,3,4,5) + SE channel attention + Concat Pooling.
3. Focal Loss (gamma=2.0) with label smoothing (alpha=0.05) to suppress false positives.
4. Cosine Annealing learning rate schedule.
5. Temperature Scaling probability calibration.
6. Granular holdout evaluation across all 5 original corpora and user feedback via source-tag filtering.
7. Verified ONNX export to extension/models/email-threat.onnx.
"""

import os
import sys
import time
import argparse
import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import onnx

sys.path.insert(0, os.path.abspath("."))
from tools.ml_text.model import TextThreatNet
from tools.ml_text.dataset import MasterTextDataset, FastMasterTextBatchLoader
from tools.ml_common import FocalLoss, TemperatureCalibrator


def evaluate_master(model, loader, device, calibrator=None):
    model.eval()
    preds = []
    labels = []
    probs = []
    raw_logits_list = []

    with torch.no_grad():
        for ids, mask, lbls in loader:
            ids = ids.to(device)
            mask = mask.to(device)
            logits = model(ids, mask)
            if calibrator is not None:
                logits = calibrator(logits)
            p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            pr = torch.argmax(logits, dim=1).cpu().numpy()
            probs.extend(p)
            preds.extend(pr)
            labels.extend(lbls.numpy())
            raw_logits_list.append(logits.cpu())

    preds = np.array(preds)
    labels = np.array(labels)
    probs = np.array(probs)

    acc = accuracy_score(labels, preds)
    prec = precision_score(labels, preds, zero_division=0)
    rec = recall_score(labels, preds, zero_division=0)
    f1 = f1_score(labels, preds, zero_division=0)
    auc = roc_auc_score(labels, probs) if len(np.unique(labels)) > 1 else 1.0
    safe_mask = (labels == 0)
    fpr = np.mean(preds[safe_mask] == 1) if np.sum(safe_mask) > 0 else 0.0

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "fpr": fpr,
        "count": len(labels),
        "logits": torch.cat(raw_logits_list, dim=0) if raw_logits_list else None,
        "preds": preds,
        "labels": labels
    }


def evaluate_indices(model, dataset, indices, device, batch_size=512, calibrator=None):
    model.eval()
    preds = []
    labels = []
    probs = []

    with torch.no_grad():
        for i in range(0, len(indices), batch_size):
            batch_idx = indices[i : i + batch_size]
            ids, mask, lbls = dataset.get_batch(batch_idx)
            ids = ids.to(device)
            mask = mask.to(device)
            logits = model(ids, mask)
            if calibrator is not None:
                logits = calibrator(logits)
            p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            pr = torch.argmax(logits, dim=1).cpu().numpy()
            probs.extend(p)
            preds.extend(pr)
            labels.extend(lbls.numpy())

    preds = np.array(preds)
    labels = np.array(labels)
    probs = np.array(probs)

    acc = accuracy_score(labels, preds)
    prec = precision_score(labels, preds, zero_division=0)
    rec = recall_score(labels, preds, zero_division=0)
    f1 = f1_score(labels, preds, zero_division=0)
    auc = roc_auc_score(labels, probs) if len(np.unique(labels)) > 1 else 1.0
    safe_mask = (labels == 0)
    fpr = np.mean(preds[safe_mask] == 1) if np.sum(safe_mask) > 0 else 0.0

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "fpr": fpr,
        "count": len(labels)
    }


def export_onnx(model, export_path, device):
    model.eval()
    dummy_ids = torch.zeros(1, 128, dtype=torch.int64, device=device)
    dummy_mask = torch.ones(1, 128, dtype=torch.int64, device=device)

    os.makedirs(os.path.dirname(export_path), exist_ok=True)
    torch.onnx.export(
        model,
        (dummy_ids, dummy_mask),
        export_path,
        export_params=True,
        opset_version=14,
        do_constant_folding=True,
        dynamo=False,
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "logits": {0: "batch_size"}
        }
    )
    onnx_model = onnx.load(export_path)
    onnx.checker.check_model(onnx_model)
    file_size_mb = os.path.getsize(export_path) / (1024 * 1024)
    print(f"[*] Verified & Exported ONNX to {export_path} ({file_size_mb:.2f} MB)")


def main():
    parser = argparse.ArgumentParser(description="Train Model on Consolidated Master Email Dataset")
    parser.add_argument("--bin-path", type=str, default="data/processed/text/master_emails.bin")
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=8e-4)
    parser.add_argument("--checkpoint-out", type=str, default="data/models/email_unified.pt")
    parser.add_argument("--export-onnx", type=str, default="extension/models/email-threat.onnx")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training on device: {device}")

    # Load master dataset splits
    train_ds = MasterTextDataset(args.bin_path, split="train")
    val_ds = MasterTextDataset(args.bin_path, split="val")
    test_ds = MasterTextDataset(args.bin_path, split="test")

    print("\n" + "=" * 68)
    print("       CONSOLIDATED MASTER EMAIL DATASET INITIALIZATION")
    print("=" * 68)
    print(f"  Total Master Records:     {train_ds.total_records:,}")
    print(f"  Training Samples:         {len(train_ds):,}")
    print(f"  Validation Samples:       {len(val_ds):,}")
    print(f"  Holdout Test Samples:     {len(test_ds):,}")
    print(f"  User Feedback Ingested:   {train_ds.counts.get('feedback', 0):,}")

    train_labels = train_ds.labels
    total_safe = int(np.sum(train_labels == 0))
    total_threats = int(np.sum(train_labels == 1))
    print(f"  Training Class Balance:   {total_safe:,} Safe vs {total_threats:,} Threats/Spam")

    pos_weight = total_safe / max(total_threats, 1)
    class_weights = torch.tensor([1.0, min(pos_weight, 2.0)], dtype=torch.float32, device=device)
    print(f"  Focal Loss Class Multiplier: [1.00, {class_weights[1]:.2f}]")
    print("=" * 68 + "\n")

    train_loader = FastMasterTextBatchLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = FastMasterTextBatchLoader(val_ds, batch_size=args.batch_size * 2, shuffle=False)
    test_loader = FastMasterTextBatchLoader(test_ds, batch_size=args.batch_size * 2, shuffle=False)

    model = TextThreatNet(vocab_size=16384, embed_dim=64, num_filters=64).to(device)

    criterion = FocalLoss(alpha=class_weights, gamma=2.0, label_smoothing=0.05)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs, eta_min=1e-5)

    best_val_f1 = 0.0
    start_time = time.time()

    for epoch in range(1, args.epochs + 1):
        model.train()
        epoch_loss = 0.0
        batches = 0
        ep_start = time.time()

        for ids, mask, labels in train_loader:
            ids = ids.to(device)
            mask = mask.to(device)
            labels = labels.to(device)

            optimizer.zero_grad()
            logits = model(ids, mask)
            loss = criterion(logits, labels)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
            optimizer.step()

            epoch_loss += loss.item()
            batches += 1

            if batches % 40 == 0 or batches == len(train_loader):
                print(f"  [Epoch {epoch}/{args.epochs}] Batch {batches}/{len(train_loader)} - Focal Loss: {epoch_loss/batches:.4f}")

        scheduler.step()
        ep_duration = time.time() - ep_start
        train_loss = epoch_loss / max(batches, 1)

        val_metrics = evaluate_master(model, val_loader, device)
        print(f"\n[*] Epoch [{epoch}/{args.epochs}] ({ep_duration:.1f}s) Loss: {train_loss:.4f} | "
              f"Val Acc: {val_metrics['accuracy']*100:.2f}% | "
              f"Val Prec: {val_metrics['precision']*100:.2f}% | "
              f"Val Rec: {val_metrics['recall']*100:.2f}% | "
              f"Val F1: {val_metrics['f1']*100:.2f}% | "
              f"Val AUC: {val_metrics['roc_auc']:.4f} | "
              f"Val FPR: {val_metrics['fpr']*100:.2f}%\n")

        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            os.makedirs(os.path.dirname(args.checkpoint_out), exist_ok=True)
            torch.save({
                "model_state_dict": model.state_dict(),
                "val_metrics": val_metrics,
                "epoch": epoch
            }, args.checkpoint_out)
            print(f"[*] Saved new best model checkpoint to {args.checkpoint_out}")

    total_time = time.time() - start_time
    print(f"\n[*] Master Training Complete in {total_time/60:.1f} minutes!")

    # Load best checkpoint
    best_ckpt = torch.load(args.checkpoint_out, map_location=device, weights_only=False)
    model.load_state_dict(best_ckpt["model_state_dict"])
    model.eval()

    # Temperature Scaling Calibration
    print("\n[*] Calibrating output probabilities with Temperature Scaling...")
    val_eval = evaluate_master(model, val_loader, device)
    calibrator = TemperatureCalibrator().to(device)
    val_labels_tensor = torch.from_numpy(val_ds.labels).long().to(device)
    calibrator.fit(val_eval["logits"].to(device), val_labels_tensor)
    t_val = calibrator.temperature.item()
    print(f"[*] Optimal Temperature Parameter T = {t_val:.4f}")

    print("\n" + "=" * 70)
    print("       FINAL MASTER EMAIL HOLDOUT EVALUATION (ZERO-LEAKAGE)")
    print("=" * 70)

    # Granular per-corpus breakdown using the source field in master_emails.bin
    source_names = {
        1: "Text1 (Truthful/Deceptive)",
        2: "Text2 (SMS Spam)",
        3: "Text3 (Spam Assassin)",
        4: "Text4 (Enron Phishing)",
        5: "Both (Combined Email/SMS)",
        6: "User Feedback"
    }

    test_global_indices = test_ds.indices
    test_sources = test_ds.mmap['source'][test_global_indices]

    for s_id, s_name in source_names.items():
        sub_idx = np.where(test_sources == s_id)[0]
        if len(sub_idx) == 0:
            continue
        m = evaluate_indices(model, test_ds, sub_idx, device, calibrator=calibrator)
        print(f"--- Dataset: {s_name} ({m['count']:,} Holdout Test Texts) ---")
        print(f"  Accuracy:  {m['accuracy']*100:.2f}%")
        print(f"  Precision: {m['precision']*100:.2f}%")
        print(f"  Recall:    {m['recall']*100:.2f}%")
        print(f"  F1-Score:  {m['f1']*100:.2f}%")
        print(f"  ROC-AUC:   {m['roc_auc']:.4f}")
        print(f"  FPR:       {m['fpr']*100:.2f}%")
        print()

    # Grand combined holdout
    global_metrics = evaluate_master(model, test_loader, device, calibrator=calibrator)
    print("=" * 70)
    print(f"  GRAND MASTER EMAIL TEXT BENCHMARK ({global_metrics['count']:,} UNSEEN TEXTS)")
    print("=" * 70)
    print(f"  Combined Accuracy:  {global_metrics['accuracy']*100:.2f}%")
    print(f"  Combined Precision: {global_metrics['precision']*100:.2f}%")
    print(f"  Combined Recall:    {global_metrics['recall']*100:.2f}%")
    print(f"  Combined F1-Score:  {global_metrics['f1']*100:.2f}%")
    print(f"  Combined ROC-AUC:   {global_metrics['roc_auc']:.4f}")
    print(f"  Combined FPR:       {global_metrics['fpr']*100:.2f}%")
    print("=" * 70 + "\n")

    # Export verified ONNX
    export_onnx(model, args.export_onnx, device)


if __name__ == "__main__":
    main()
