"""Enhanced Neural Network for Email/Text Threat Detection.

Features multi-scale n-gram convolutions (k=2, 3, 4, 5), Squeeze-and-Excitation (SE)
channel attention, and Adaptive Concat Pooling (Max + Avg) for high accuracy and low FPR.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class SEBlock1D(nn.Module):
    """Squeeze-and-Excitation channel attention for text feature representations."""

    def __init__(self, channels: int, reduction: int = 4):
        super().__init__()
        reduced = max(channels // reduction, 16)
        self.fc1 = nn.Linear(channels, reduced)
        self.fc2 = nn.Linear(reduced, channels)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, C, L]
        scale = x.mean(dim=-1)  # Global Average Pooling -> [B, C]
        scale = F.relu(self.fc1(scale))
        scale = torch.sigmoid(self.fc2(scale)).unsqueeze(-1)  # [B, C, 1]
        return x * scale


class TextThreatNet(nn.Module):
    """Multi-scale ConvNet + SE Attention + Concat Pooling for email threat classification.
    
    Accepts:
        input_ids: [batch_size, seq_len] tensor of WordPiece token IDs
        attention_mask: [batch_size, seq_len] binary mask (1 for valid token, 0 for pad)
    Outputs:
        logits: [batch_size, 2] classification logits [safe, threat]
    """

    def __init__(self, vocab_size: int = 16384, embed_dim: int = 64, num_filters: int = 64):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.dropout = nn.Dropout(0.20)

        # Multi-scale 1D CNN filters capturing n-grams of sizes 2, 3, 4, 5
        self.conv2 = nn.Conv1d(embed_dim, num_filters, kernel_size=2, padding=1)
        self.conv3 = nn.Conv1d(embed_dim, num_filters, kernel_size=3, padding=1)
        self.conv4 = nn.Conv1d(embed_dim, num_filters, kernel_size=4, padding=2)
        self.conv5 = nn.Conv1d(embed_dim, num_filters, kernel_size=5, padding=2)

        total_filters = num_filters * 4  # 256 filters
        self.bn = nn.BatchNorm1d(total_filters)
        self.se = SEBlock1D(total_filters, reduction=4)

        # Concat pooling (256 max + 256 avg = 512 dimensions)
        self.classifier = nn.Sequential(
            nn.Linear(total_filters * 2, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(0.25),
            nn.Linear(128, 64),
            nn.GELU(),
            nn.Dropout(0.15),
            nn.Linear(64, 2)
        )

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor = None) -> torch.Tensor:
        # [batch, seq_len] -> [batch, seq_len, embed_dim]
        seq_len = input_ids.shape[1]
        x = self.embedding(input_ids.long())

        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()
            x = x * mask

        x = self.dropout(x)
        x = x.transpose(1, 2)  # [batch, embed_dim, seq_len]

        # Multi-scale convolutions with slice normalization
        c2 = self.conv2(x)[:, :, :seq_len]
        c3 = self.conv3(x)[:, :, :seq_len]
        c4 = self.conv4(x)[:, :, :seq_len]
        c5 = self.conv5(x)[:, :, :seq_len]

        feat = torch.cat([c2, c3, c4, c5], dim=1)  # [batch, 256, seq_len]
        feat = F.gelu(self.bn(feat))
        feat = self.se(feat)  # Channel attention recalibration

        # Adaptive Concat Pooling (Max for sharp phishing trigger tokens, Avg for general tone)
        p_max = F.adaptive_max_pool1d(feat, 1).squeeze(-1)  # [batch, 256]
        p_avg = F.adaptive_avg_pool1d(feat, 1).squeeze(-1)  # [batch, 256]
        pooled = torch.cat([p_max, p_avg], dim=1)           # [batch, 512]

        logits = self.classifier(pooled)                     # [batch, 2]
        return logits
