"""Training Script for Hybrid URL Threat Neural Network.

Trains sequentially on datasets with warm-start checkpoints,
reports detailed accuracy/F1/precision/recall metrics,
and exports directly to extension/models/url-threat.onnx.
"""

import os
import argparse
import time
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from model import HybridUrlThreatNet
from dataset import BinaryUrlDataset


def parse_args():
    parser = argparse.ArgumentParser(description="Train Hybrid URL Threat Model")
    parser.add_argument("--prefix", type=str, required=True, help="Path prefix to processed dataset (e.g. data/processed/url/URL1)")
    parser.add_argument("--checkpoint-in", type=str, default=None, help="Input checkpoint for warm-start incremental training")
    parser.add_argument("--checkpoint-out", type=str, default="data/models/url_threat_checkpoint.pt", help="Path to save output checkpoint")
    parser.add_argument("--export-onnx", type=str, default="extension/models/url-threat.onnx", help="Path to export ONNX model")
    parser.add_argument("--epochs", type=int, default=5, help="Number of epochs to train")
    parser.add_argument("--batch-size", type=int, default=512, help="Batch size for training")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--pos-weight", type=float, default=None, help="Positive class weight multiplier (default: auto capped at 2.0)")
    return parser.parse_args()


def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    all_preds = []
    all_labels = []
    all_probs = []

    with torch.no_grad():
        for feats, chars, labels in loader:
            feats = feats.to(device)
            chars = chars.to(device)
            labels = labels.to(device)

            logits = model(feats, chars)
            loss = criterion(logits, labels)
            total_loss += loss.item() * len(labels)

            probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            preds = torch.argmax(logits, dim=1).cpu().numpy()

            all_preds.extend(preds)
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs)

    total_samples = len(all_labels)
    avg_loss = total_loss / total_samples
    acc = accuracy_score(all_labels, all_preds)
    prec = precision_score(all_labels, all_preds, zero_division=0)
    rec = recall_score(all_labels, all_preds, zero_division=0)
    f1 = f1_score(all_labels, all_preds, zero_division=0)
    
    try:
        auc = roc_auc_score(all_labels, all_probs)
    except Exception:
        auc = 0.0

    # False Positive Rate: False Positives / All Actual Negatives
    neg_mask = np.array(all_labels) == 0
    fp = np.sum((np.array(all_preds) == 1) & neg_mask)
    fpr = fp / max(np.sum(neg_mask), 1)

    return {
        "loss": avg_loss,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "auc": auc,
        "fpr": fpr
    }


def export_to_onnx(model, export_path, device):
    os.makedirs(os.path.dirname(export_path), exist_ok=True)
    model.eval()

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

    import onnx
    onnx_model = onnx.load(export_path)
    onnx.checker.check_model(onnx_model)
    size_mb = os.path.getsize(export_path) / (1024 * 1024)
    print(f"[*] ONNX model successfully verified and exported to {export_path} ({size_mb:.2f} MB)")


def main():
    args = parse_args()
    device = torch.device("cpu")
    print(f"\n=======================================================")
    print(f"  Training URL Threat Model: {os.path.basename(args.prefix)}")
    print(f"=======================================================")

    # Load datasets
    train_ds = BinaryUrlDataset(args.prefix, split="train")
    val_ds = BinaryUrlDataset(args.prefix, split="val")
    test_ds = BinaryUrlDataset(args.prefix, split="test")

    print(f"Dataset Split Sizes:")
    print(f"  Train: {len(train_ds):,} samples")
    print(f"  Val:   {len(val_ds):,} samples")
    print(f"  Test:  {len(test_ds):,} samples")

    # Calculate class weighting for loss
    train_labels = train_ds.labels[:]
    pos_count = int(np.sum(train_labels == 1))
    neg_count = int(np.sum(train_labels == 0))
    if args.pos_weight is not None:
        pos_weight = args.pos_weight
    else:
        raw_ratio = neg_count / max(pos_count, 1)
        pos_weight = min(raw_ratio, 2.0)
    class_weights = torch.tensor([1.0, pos_weight], dtype=torch.float32, device=device)
    print(f"Class Balance: {neg_count:,} Benign vs {pos_count:,} Threats (Weight multiplier: {class_weights[1]:.2f})")

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, drop_last=False)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False)

    # Initialize model
    model = HybridUrlThreatNet(feature_dim=32, char_seq_len=128, vocab_size=135).to(device)

    # Warm-start if prior checkpoint supplied
    if args.checkpoint_in and os.path.exists(args.checkpoint_in):
        print(f"Warm-starting from checkpoint: {args.checkpoint_in}")
        checkpoint = torch.load(args.checkpoint_in, map_location=device, weights_only=False)
        model.load_state_dict(checkpoint["model_state_dict"])
        # Use smaller learning rate for fine-tuning
        args.lr = args.lr * 0.5
        print(f"Adjusted fine-tuning learning rate to: {args.lr:.2e}")

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs, eta_min=1e-5)

    best_val_f1 = 0.0
    best_state = None
    start_time = time.time()

    for epoch in range(1, args.epochs + 1):
        model.train()
        epoch_loss = 0.0
        batches = 0

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

        scheduler.step()
        train_loss = epoch_loss / max(batches, 1)

        val_metrics = evaluate(model, val_loader, criterion, device)
        print(f"Epoch [{epoch}/{args.epochs}] Loss: {train_loss:.4f} | "
              f"Val Acc: {val_metrics['accuracy']*100:.2f}% | "
              f"Val Prec: {val_metrics['precision']*100:.2f}% | "
              f"Val Rec: {val_metrics['recall']*100:.2f}% | "
              f"Val F1: {val_metrics['f1']*100:.2f}% | "
              f"Val AUC: {val_metrics['auc']:.4f} | "
              f"FPR: {val_metrics['fpr']*100:.2f}%")

        if val_metrics["f1"] >= best_val_f1:
            best_val_f1 = val_metrics["f1"]
            best_state = model.state_dict().copy()

    # Restore best validation state
    if best_state is not None:
        model.load_state_dict(best_state)

    # Save output checkpoint
    os.makedirs(os.path.dirname(args.checkpoint_out), exist_ok=True)
    torch.save({
        "model_state_dict": model.state_dict(),
        "best_val_f1": best_val_f1,
        "dataset": args.prefix,
        "timestamp": time.time()
    }, args.checkpoint_out)
    print(f"\n[*] Saved model checkpoint to {args.checkpoint_out}")

    # Final holdout test evaluation
    test_metrics = evaluate(model, test_loader, criterion, device)
    elapsed = time.time() - start_time

    print(f"\n-------------------------------------------------------")
    print(f"  Holdout Test Evaluation: {os.path.basename(args.prefix)} ({elapsed:.1f}s)")
    print(f"-------------------------------------------------------")
    print(f"  Accuracy:  {test_metrics['accuracy']*100:.2f}%")
    print(f"  Precision: {test_metrics['precision']*100:.2f}%")
    print(f"  Recall:    {test_metrics['recall']*100:.2f}%")
    print(f"  F1-Score:  {test_metrics['f1']*100:.2f}%")
    print(f"  ROC-AUC:   {test_metrics['auc']:.4f}")
    print(f"  FPR:       {test_metrics['fpr']*100:.2f}% (False Positive Rate on Safe URLs)")
    print(f"-------------------------------------------------------")

    # Export to ONNX for browser extension
    if args.export_onnx:
        export_to_onnx(model, args.export_onnx, device)


if __name__ == "__main__":
    main()

