import os
import json
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from model import HybridUrlThreatNet
from dataset import BinaryUrlDataset

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Evaluating Final Model on device: {device}")

    checkpoint_path = "data/models/url_stage4.pt"
    if not os.path.exists(checkpoint_path):
        print(f"Error: {checkpoint_path} not found")
        return

    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    model = HybridUrlThreatNet(feature_dim=32, char_seq_len=128, vocab_size=135).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    datasets = ["URL1", "URL2", "URL3", "URL4"]
    total_samples = 0
    total_correct = 0
    all_all_preds = []
    all_all_labels = []
    all_all_probs = []

    print("\n" + "=" * 70)
    print("      FINAL MULTI-DATASET HOLDOUT EVALUATION (ZERO-LEAKAGE)")
    print("=" * 70)

    for ds_name in datasets:
        prefix = f"data/processed/url/{ds_name}"
        test_ds = BinaryUrlDataset(prefix, split="test")
        loader = DataLoader(test_ds, batch_size=2048, shuffle=False)

        preds = []
        labels = []
        probs = []

        with torch.no_grad():
            for f, c, l in loader:
                f = f.to(device)
                c = c.to(device)
                logits = model(f, c)
                p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
                pr = torch.argmax(logits, dim=1).cpu().numpy()
                probs.extend(p)
                preds.extend(pr)
                labels.extend(l.numpy())

        preds = np.array(preds)
        labels = np.array(labels)
        probs = np.array(probs)

        acc = accuracy_score(labels, preds)
        prec = precision_score(labels, preds, zero_division=0)
        rec = recall_score(labels, preds, zero_division=0)
        f1 = f1_score(labels, preds, zero_division=0)
        auc = roc_auc_score(labels, probs)
        
        safe_mask = (labels == 0)
        fpr = np.mean(preds[safe_mask] == 1) if np.sum(safe_mask) > 0 else 0.0

        print(f"\n--- Dataset: {ds_name} (Holdout Test: {len(labels):,} samples) ---")
        print(f"  Accuracy:  {acc * 100:.2f}%")
        print(f"  Precision: {prec * 100:.2f}%")
        print(f"  Recall:    {rec * 100:.2f}%")
        print(f"  F1-Score:  {f1 * 100:.2f}%")
        print(f"  ROC-AUC:   {auc:.4f}")
        print(f"  FPR:       {fpr * 100:.2f}% (False Positive Rate on Safe URLs)")

        all_all_preds.extend(preds)
        all_all_labels.extend(labels)
        all_all_probs.extend(probs)

    # Combined Global Holdout Metrics across all 206,144 unseen samples
    all_all_preds = np.array(all_all_preds)
    all_all_labels = np.array(all_all_labels)
    all_all_probs = np.array(all_all_probs)

    global_acc = accuracy_score(all_all_labels, all_all_preds)
    global_prec = precision_score(all_all_labels, all_all_preds, zero_division=0)
    global_rec = recall_score(all_all_labels, all_all_preds, zero_division=0)
    global_f1 = f1_score(all_all_labels, all_all_preds, zero_division=0)
    global_auc = roc_auc_score(all_all_labels, all_all_probs)
    
    global_safe_mask = (all_all_labels == 0)
    global_fpr = np.mean(all_all_preds[global_safe_mask] == 1)

    print("\n" + "=" * 70)
    print(f"  GRAND COMBINED HOLDOUT BENCHMARK ({len(all_all_labels):,} UNSEEN SAMPLES)")
    print("=" * 70)
    print(f"  Combined Accuracy:  {global_acc * 100:.2f}%")
    print(f"  Combined Precision: {global_prec * 100:.2f}%")
    print(f"  Combined Recall:    {global_rec * 100:.2f}%")
    print(f"  Combined F1-Score:  {global_f1 * 100:.2f}%")
    print(f"  Combined ROC-AUC:   {global_auc:.4f}")
    print(f"  Combined FPR:       {global_fpr * 100:.2f}%")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
