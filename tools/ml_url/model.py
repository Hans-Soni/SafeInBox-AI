"""Enhanced Hybrid Neural Network for URL Threat Classification.

Combines high-level domain/URL heuristic signals (32 dense features)
with raw character sequence representations (128 character embeddings)
using Multi-Scale Inception Convolutions, Squeeze-and-Excitation Channel Attention,
and Dual-Pooling (Max + Avg) for superior detection of obfuscated threats.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class SEBlock1D(nn.Module):
    """Squeeze-and-Excitation channel attention for 1D feature maps."""

    def __init__(self, channels: int, reduction: int = 4):
        super().__init__()
        reduced = max(channels // reduction, 8)
        self.fc1 = nn.Linear(channels, reduced)
        self.fc2 = nn.Linear(reduced, channels)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, C, L]
        scale = x.mean(dim=-1)  # Global Average Pooling -> [B, C]
        scale = F.relu(self.fc1(scale))
        scale = torch.sigmoid(self.fc2(scale)).unsqueeze(-1)  # [B, C, 1]
        return x * scale


class HybridUrlThreatNet(nn.Module):
    """Dual-branch hybrid architecture matching the Chrome extension's ONNX contract.
    
    Accepts:
        features: [B, 32] float32 tensor
        characters: [B, 128] int32 tensor
    Outputs:
        output: [B, 2] float32 logits [safe_logit, threat_logit]
    """

    def __init__(
        self,
        feature_dim: int = 32,
        char_seq_len: int = 128,
        vocab_size: int = 135,
        char_emb_dim: int = 24,
        branch_channels: int = 24,
    ):
        super().__init__()
        self.char_seq_len = char_seq_len

        # Branch 1: Dense Heuristic Signal Network with Residual Skip
        self.feat_in = nn.Linear(feature_dim, 64)
        self.feat_bn1 = nn.BatchNorm1d(64)
        self.feat_fc2 = nn.Linear(64, 64)
        self.feat_bn2 = nn.BatchNorm1d(64)
        self.feat_out = nn.Linear(64, 48)
        self.feat_bn3 = nn.BatchNorm1d(48)
        self.feat_dropout = nn.Dropout(0.20)

        # Branch 2: Multi-Scale Character-Level ConvNet (k=2, 3, 5, 7)
        self.char_embedding = nn.Embedding(vocab_size, char_emb_dim, padding_idx=0)
        self.conv2 = nn.Conv1d(char_emb_dim, branch_channels, kernel_size=2, padding=1)
        self.conv3 = nn.Conv1d(char_emb_dim, branch_channels, kernel_size=3, padding=1)
        self.conv5 = nn.Conv1d(char_emb_dim, branch_channels, kernel_size=5, padding=2)
        self.conv7 = nn.Conv1d(char_emb_dim, branch_channels, kernel_size=7, padding=3)

        total_conv_channels = branch_channels * 4  # 96 channels
        self.bn_conv = nn.BatchNorm1d(total_conv_channels)
        self.se_block = SEBlock1D(total_conv_channels, reduction=4)

        # Dual pooling: 96 (max) + 96 (avg) = 192 features
        self.char_fc = nn.Sequential(
            nn.Linear(total_conv_channels * 2, 48),
            nn.BatchNorm1d(48),
            nn.GELU(),
            nn.Dropout(0.15)
        )

        # Fusion & Multi-Class Head ([safe_logit, threat_logit])
        # Dense (48) + Char (48) = 96
        self.classifier = nn.Sequential(
            nn.Linear(48 + 48, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(0.20),
            nn.Linear(64, 32),
            nn.GELU(),
            nn.Linear(32, 2)
        )

    def forward(self, features: torch.Tensor, characters: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            features: [batch_size, 32] float32 tensor of heuristic features.
            characters: [batch_size, 128] int32 tensor of character vocabulary tokens.

        Returns:
            logits: [batch_size, 2] float32 tensor of class logits [safe, threat].
        """
        # Branch 1: Heuristic processing with residual connection
        h1 = F.gelu(self.feat_bn1(self.feat_in(features)))
        h1 = self.feat_dropout(h1)
        h2 = F.gelu(self.feat_bn2(self.feat_fc2(h1))) + h1  # Skip connection
        feat_repr = F.gelu(self.feat_bn3(self.feat_out(h2)))  # [B, 48]

        # Branch 2: Character sequence multi-scale extraction
        char_emb = self.char_embedding(characters.long()).transpose(1, 2)  # [B, emb_dim, seq_len]
        c2 = self.conv2(char_emb)[:, :, :self.char_seq_len]
        c3 = self.conv3(char_emb)
        c5 = self.conv5(char_emb)
        c7 = self.conv7(char_emb)

        multi_scale = torch.cat([c2, c3, c5, c7], dim=1)  # [B, 96, 128]
        multi_scale = F.gelu(self.bn_conv(multi_scale))
        multi_scale = self.se_block(multi_scale)

        # Dual Pooling (Adaptive Max + Average)
        p_max = F.adaptive_max_pool1d(multi_scale, 1).squeeze(-1)  # [B, 96]
        p_avg = F.adaptive_avg_pool1d(multi_scale, 1).squeeze(-1)  # [B, 96]
        char_pooled = torch.cat([p_max, p_avg], dim=1)  # [B, 192]
        char_repr = self.char_fc(char_pooled)  # [B, 48]

        # Fusion & Classification
        fused = torch.cat([feat_repr, char_repr], dim=1)  # [B, 96]
        logits = self.classifier(fused)  # [B, 2]
        return logits
