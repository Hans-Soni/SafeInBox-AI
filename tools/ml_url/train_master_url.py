"""Ultra-Fast Master URL Model Training using Vectorized Memory-Mapped Slicing.

Implements:
1. MasterUrlDataset & FastMasterBatchLoader: Zero-copy C-level array slicing.
2. Inception Multi-Scale Character Convolutions + SE Channel Attention + Dual Pooling.
3. Focal Loss (gamma=2.0) with label smoothing (alpha=0.05).
4. Temperature Scaling probability calibration.
5. Granular holdout evaluation across all original corpora and user feedback.
6. Clean ONNX export to extension/models/url-threat.onnx.
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
from tools.ml_url.model import HybridUrlThreatNet
from tools.ml_url.dataset import MasterUrlDataset, FastMasterBatchLoader
from tools.ml_common import FocalLoss, TemperatureCalibrator


def evaluate_master(model, loader, device, calibrator=None):
    model.eval()
    preds = []
    labels = []
    probs = []
    raw_logits_list = []

    with torch.no_grad():
        for feats, chars, lbls in loader:
            feats = feats.to(device)
            chars = chars.to(device)
            logits = model(feats, chars)
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


def export_onnx(model, export_path, device):
    model.eval()
    dummy_feats = torch.zeros(1, 32, dtype=torch.float32, device=device)
    dummy_chars = torch.zeros(1, 128, dtype=torch.int32, device=device)

    os.makedirs(os.path.dirname(export_path), exist_ok=True)
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
    file_size_kb = os.path.getsize(export_path) / 1024
    print(f"[*] Verified & Exported ONNX to {export_path} ({file_size_kb:.1f} KB)")


def main():
    parser = argparse.ArgumentParser(description="Train Model on Consolidated Master URL Dataset")
    parser.add_argument("--bin-path", type=str, default="data/processed/url/master_urls.bin")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--lr", type=float, default=6e-4)
    parser.add_argument("--checkpoint-out", type=str, default="data/models/url_unified.pt")
    parser.add_argument("--export-onnx", type=str, default="extension/models/url-threat.onnx")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training on device: {device}")

    # Load master dataset splits
    train_ds = MasterUrlDataset(args.bin_path, split="train")
    val_ds = MasterUrlDataset(args.bin_path, split="val")
    test_ds = MasterUrlDataset(args.bin_path, split="test")

    print("\n" + "=" * 68)
    print("       CONSOLIDATED MASTER URL DATASET INITIALIZATION")
    print("=" * 68)
    print(f"  Total Master Records:     {train_ds.total_records:,}")
    print(f"  Training Samples:         {len(train_ds):,}")
    print(f"  Validation Samples:       {len(val_ds):,}")
    print(f"  Holdout Test Samples:     {len(test_ds):,}")
    print(f"  User Feedback Ingested:   {train_ds.counts.get('feedback', 0):,}")

    train_labels = train_ds.labels
    total_threats = int(np.sum(train_labels == 1))
    total_benign = int(np.sum(train_labels == 0))
    pos_weight = total_benign / max(total_threats, 1)
    class_weights = torch.tensor([1.0, min(pos_weight, 2.0)], dtype=torch.float32, device=device)
    print(f"  Class Balance: {total_benign:,} Benign vs {total_threats:,} Threats")
    print(f"  Focal Loss Class Multiplier: [1.00, {class_weights[1]:.2f}]")
    print("=" * 68 + "\n")

    train_loader = FastMasterBatchLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = FastMasterBatchLoader(val_ds, batch_size=args.batch_size * 2, shuffle=False)

    model = HybridUrlThreatNet(feature_dim=32, char_seq_len=128, vocab_size=135).to(device)

    # Focal Loss (gamma=2.0) with label smoothing (alpha=0.05)
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

        for feats, chars, labels in train_loader:
            feats = feats.to(device)
            chars = chars.to(device)
            labels = labels.to(device)

            optimizer.zero_grad()
            logits = model(feats, chars)
            loss = criterion(logits, labels)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
            optimizer.step()

            epoch_loss += loss.item()
            batches += 1

            if batches % 100 == 0 or batches == len(train_loader):
                print(f"  [Epoch {epoch}/{args.epochs}] Batch {batches}/{len(train_loader)} - Focal Loss: {epoch_loss/batches:.4f}")

        scheduler.step()
        ep_duration = time.time() - ep_start
        train_loss = epoch_loss / max(batches, 1)

        val_metrics = evaluate_master(model, val_loader, device)
        print(f"\n[*] Epoch [{epoch}/{args.epochs}] in {ep_duration:.1f}s (Loss: {train_loss:.4f}) | "
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
    print(f"\n[*] Training Complete in {total_time/60:.1f} minutes!")

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
    print(f"[*] Optimal Temperature Parameter T = {calibrator.temperature.item():.4f}")

    print("\n" + "=" * 70)
    print("       FINAL MASTER URL HOLDOUT EVALUATION (ZERO-LEAKAGE)")
    print("=" * 70)

    # Evaluate across overall holdout test set
    test_loader = FastMasterBatchLoader(test_ds, batch_size=args.batch_size * 2, shuffle=False)
    global_metrics = evaluate_master(model, test_loader, device, calibrator=calibrator)

    # Granular breakdown by original corpus source
    source_names = {1: "URL1", 2: "URL2", 3: "URL3", 4: "URL4", 5: "User Feedback"}
    test_recs = test_ds.mmap[test_ds.indices]
    test_sources = test_recs['source']

    for src_id, src_name in source_names.items():
        sub_mask = (test_sources == src_id)
        if np.sum(sub_mask) == 0:
            continue
        sub_preds = global_metrics["preds"][sub_mask]
        sub_labels = global_metrics["labels"][sub_mask]
        sub_acc = accuracy_score(sub_labels, sub_preds)
        sub_rec = recall_score(sub_labels, sub_preds, zero_division=0)
        sub_prec = precision_score(sub_labels, sub_preds, zero_division=0)
        sub_f1 = f1_score(sub_labels, sub_preds, zero_division=0)
        sub_safe = (sub_labels == 0)
        sub_fpr = np.mean(sub_preds[sub_safe] == 1) if np.sum(sub_safe) > 0 else 0.0

        print(f"--- Corpus: {src_name} ({len(sub_labels):,} Holdout Samples) ---")
        print(f"  Accuracy:  {sub_acc * 100:.2f}%")
        print(f"  Precision: {sub_prec * 100:.2f}%")
        print(f"  Recall:    {sub_rec * 100:.2f}%")
        print(f"  F1-Score:  {sub_f1 * 100:.2f}%")
        print(f"  FPR:       {sub_fpr * 100:.2f}%")
        print()

    print("=" * 70)
    print(f"  GRAND MASTER BENCHMARK ({global_metrics['count']:,} UNSEEN SAMPLES)")
    print("=" * 70)
    print(f"  Combined Accuracy:  {global_metrics['accuracy']*100:.2f}%")
    print(f"  Combined Precision: {global_metrics['precision']*100:.2f}%")
    print(f"  Combined Recall:    {global_metrics['recall']*100:.2f}%")
    print(f"  Combined F1-Score:  {global_metrics['f1']*100:.2f}%")
    print(f"  Combined ROC-AUC:   {global_metrics['roc_auc']:.4f}")
    print(f"  Combined FPR:       {global_metrics['fpr']*100:.2f}%")
    print("=" * 70 + "\n")

    # Export final verified ONNX to extension
    export_onnx(model, args.export_onnx, device)


if __name__ == "__main__":
    main()
