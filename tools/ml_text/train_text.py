"""Enhanced Multi-Corpus Neural Network Training for Email/Text Threat Detection.

Features:
1. Multi-scale n-gram convolutions (k=2, 3, 4, 5) with SE channel attention & Concat Pooling (TextThreatNet).
2. Focal Loss with label smoothing (gamma=2.0, alpha class weighting) to suppress false positives on urgent business emails.
3. Cosine Annealing learning rate schedule.
4. Post-hoc Temperature Scaling / Probability Calibration.
5. Zero-leakage holdout evaluation across all 5 text corpora and verified ONNX export.
"""

import os
import sys
import time
import argparse
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, ConcatDataset
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import onnx

sys.path.insert(0, os.path.abspath("."))
from tools.ml_text.model import TextThreatNet
from tools.ml_text.dataset import BinaryTextDataset
from tools.ml_common import FocalLoss, TemperatureCalibrator


def evaluate_dataset(model, ds, device, batch_size=512, calibrator=None):
    model.eval()
    loader = DataLoader(ds, batch_size=batch_size, shuffle=False)
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
        "logits": torch.cat(raw_logits_list, dim=0) if raw_logits_list else None
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
    print(f"[*] Exported and verified ONNX model at {export_path} ({file_size_mb:.2f} MB)")


def main():
    parser = argparse.ArgumentParser(description="Train Enhanced Multi-Corpus Email Threat Model")
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=8e-4)
    parser.add_argument("--checkpoint-out", type=str, default="data/models/email_threat_model.pt")
    parser.add_argument("--export-onnx", type=str, default="extension/models/email-threat.onnx")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training Enhanced Email Threat Model on device: {device}")

    dataset_names = ["text1", "text2", "text3", "text4", "both"]
    train_datasets = []
    val_datasets = []
    test_datasets = []

    total_train = 0
    total_val = 0
    total_test = 0
    total_threats = 0
    total_safe = 0

    for name in dataset_names:
        prefix = f"data/processed/text/{name}"
        t_ds = BinaryTextDataset(prefix, split="train")
        v_ds = BinaryTextDataset(prefix, split="val")
        te_ds = BinaryTextDataset(prefix, split="test")

        train_datasets.append(t_ds)
        val_datasets.append(v_ds)
        test_datasets.append(te_ds)

        total_train += len(t_ds)
        total_val += len(v_ds)
        total_test += len(te_ds)

        t_lbls = t_ds.labels[:]
        total_threats += int(np.sum(t_lbls == 1))
        total_safe += int(np.sum(t_lbls == 0))

    unified_train = ConcatDataset(train_datasets)
    unified_val = ConcatDataset(val_datasets)

    print("\n" + "=" * 68)
    print("       ENHANCED UNIFIED EMAIL TEXT CORPUS INITIALIZATION")
    print("=" * 68)
    print(f"  Total Training Samples:   {total_train:,}")
    print(f"  Total Validation Samples: {total_val:,}")
    print(f"  Total Holdout Test:       {total_test:,}")
    print(f"  Grand Total Texts:        {total_train + total_val + total_test:,}")
    print(f"  Class Balance: {total_safe:,} Safe vs {total_threats:,} Threats/Spam")

    pos_weight = total_safe / max(total_threats, 1)
    class_weights = torch.tensor([1.0, min(pos_weight, 2.0)], dtype=torch.float32, device=device)
    print(f"  Focal Loss Class Multiplier: [1.00, {class_weights[1]:.2f}]")
    print("=" * 68 + "\n")

    train_loader = DataLoader(unified_train, batch_size=args.batch_size, shuffle=True, drop_last=False)

    model = TextThreatNet(vocab_size=16384, embed_dim=64, num_filters=64).to(device)

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

            if batches % 50 == 0 or batches == len(train_loader):
                print(f"  [Epoch {epoch}/{args.epochs}] Batch {batches}/{len(train_loader)} - Focal Loss: {epoch_loss/batches:.4f}")

        scheduler.step()
        ep_duration = time.time() - ep_start
        train_loss = epoch_loss / max(batches, 1)

        val_metrics = evaluate_dataset(model, unified_val, device, batch_size=args.batch_size * 2)
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
    print(f"\n[*] Training Complete in {total_time/60:.1f} minutes!")

    # Load best checkpoint
    best_ckpt = torch.load(args.checkpoint_out, map_location=device, weights_only=False)
    model.load_state_dict(best_ckpt["model_state_dict"])
    model.eval()

    # Temperature Scaling Calibration
    print("\n[*] Calibrating output probabilities with Temperature Scaling...")
    val_eval = evaluate_dataset(model, unified_val, device, batch_size=args.batch_size * 2)
    calibrator = TemperatureCalibrator().to(device)
    val_labels_tensor = torch.cat([torch.from_numpy(ds.labels[:]) for ds in val_datasets]).long().to(device)
    calibrator.fit(val_eval["logits"].to(device), val_labels_tensor)
    print(f"[*] Optimal Temperature Parameter T = {calibrator.temperature.item():.4f}")

    print("\n" + "=" * 70)
    print("       FINAL ENHANCED TEXT HOLDOUT EVALUATION (ZERO-LEAKAGE)")
    print("=" * 70)

    for name, te_ds in zip(dataset_names, test_datasets):
        metrics = evaluate_dataset(model, te_ds, device, batch_size=args.batch_size * 2, calibrator=calibrator)
        print(f"--- Dataset: {name} ({metrics['count']:,} Holdout Test Texts) ---")
        print(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
        print(f"  Precision: {metrics['precision']*100:.2f}%")
        print(f"  Recall:    {metrics['recall']*100:.2f}%")
        print(f"  F1-Score:  {metrics['f1']*100:.2f}%")
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
        print(f"  FPR:       {metrics['fpr']*100:.2f}%")
        print()

    # Grand combined holdout
    unified_test = ConcatDataset(test_datasets)
    global_metrics = evaluate_dataset(model, unified_test, device, batch_size=args.batch_size * 2, calibrator=calibrator)

    print("=" * 70)
    print(f"  GRAND ENHANCED TEXT BENCHMARK ({global_metrics['count']:,} UNSEEN TEXTS)")
    print("=" * 70)
    print(f"  Combined Accuracy:  {global_metrics['accuracy']*100:.2f}%")
    print(f"  Combined Precision: {global_metrics['precision']*100:.2f}%")
    print(f"  Combined Recall:    {global_metrics['recall']*100:.2f}%")
    print(f"  Combined F1-Score:  {global_metrics['f1']*100:.2f}%")
    print(f"  Combined ROC-AUC:   {global_metrics['roc_auc']:.4f}")
    print(f"  Combined FPR:       {global_metrics['fpr']*100:.2f}%")
    print("=" * 70 + "\n")

    # Export final verified ONNX
    export_onnx(model, args.export_onnx, device)


if __name__ == "__main__":
    main()
