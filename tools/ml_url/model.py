"""Hybrid Neural Network for URL Threat Classification.

Combines high-level domain/URL heuristic signals (32 dense features)
with raw character sequence representations (128 character embeddings).
"""

import torch
import torch.nn as nn


class HybridUrlThreatNet(nn.Module):
    """Dual-branch hybrid architecture matching the Chrome extension's ONNX contract."""

    def __init__(self, feature_dim: int = 32, char_seq_len: int = 128, vocab_size: int = 135, char_emb_dim: int = 16):
        super().__init__()
        # Branch 1: Dense Heuristic Signal Network
        self.feature_net = nn.Sequential(
            nn.Linear(feature_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.25),
            nn.Linear(64, 48),
            nn.BatchNorm1d(48),
            nn.ReLU(),
        )

        # Branch 2: Character-Level 1D Convolution Network
        self.char_embedding = nn.Embedding(vocab_size, char_emb_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(char_emb_dim, 32, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(32, 32, kernel_size=5, padding=2)
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.char_fc = nn.Sequential(
            nn.Linear(32, 32),
            nn.BatchNorm1d(32),
            nn.ReLU()
        )

        # Fusion & Multi-Class Head ([safe_logit, threat_logit])
        self.classifier = nn.Sequential(
            nn.Linear(48 + 32, 48),
            nn.BatchNorm1d(48),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(48, 2)
        )

    def forward(self, features: torch.Tensor, characters: torch.Tensor) -> torch.Tensor:
        """Forward pass.
        
        Args:
            features: [batch_size, 32] float32 tensor of heuristic features.
            characters: [batch_size, 128] int32 tensor of character vocabulary tokens.
        
        Returns:
            logits: [batch_size, 2] float32 tensor of class logits [safe, threat].
        """
        # Process heuristic features
        feat_repr = self.feature_net(features)

        # Process character sequences
        char_emb = self.char_embedding(characters.long()).transpose(1, 2)  # [B, emb_dim, seq_len]
        c1 = torch.relu(self.conv1(char_emb))
        c2 = torch.relu(self.conv2(c1))
        pooled = self.pool(c2).squeeze(2)  # [B, 32]
        char_repr = self.char_fc(pooled)

        # Fuse representations and compute logits
        fused = torch.cat([feat_repr, char_repr], dim=1)
        logits = self.classifier(fused)
        return logits

