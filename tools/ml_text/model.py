"""Lightweight, High-Accuracy Neural Network for Email/Text Threat Detection."""

import torch
import torch.nn as nn
import torch.nn.functional as F


class TextThreatNet(nn.Module):
    """
    Multi-scale ConvNet text threat classifier for email, SMS, and phishing text.
    Accepts input_ids and attention_mask tensors and produces binary logits [safe, threat].
    """

    def __init__(self, vocab_size: int = 16384, embed_dim: int = 64, num_filters: int = 64):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.dropout = nn.Dropout(0.2)

        # Multi-scale 1D CNN filters for capturing n-grams of sizes 2, 3, 4, 5
        self.conv2 = nn.Conv1d(embed_dim, num_filters, kernel_size=2, padding=1)
        self.conv3 = nn.Conv1d(embed_dim, num_filters, kernel_size=3, padding=1)
        self.conv4 = nn.Conv1d(embed_dim, num_filters, kernel_size=4, padding=2)
        self.conv5 = nn.Conv1d(embed_dim, num_filters, kernel_size=5, padding=2)

        self.bn2 = nn.BatchNorm1d(num_filters)
        self.bn3 = nn.BatchNorm1d(num_filters)
        self.bn4 = nn.BatchNorm1d(num_filters)
        self.bn5 = nn.BatchNorm1d(num_filters)

        total_filters = num_filters * 4
        self.fc1 = nn.Linear(total_filters, 64)
        self.fc2 = nn.Linear(64, 2)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor = None) -> torch.Tensor:
        # [batch, seq_len] -> [batch, seq_len, embed_dim]
        x = self.embedding(input_ids)
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()
            x = x * mask

        x = self.dropout(x)
        x = x.transpose(1, 2)  # [batch, embed_dim, seq_len]

        c2 = F.relu(self.bn2(self.conv2(x)))
        c3 = F.relu(self.bn3(self.conv3(x)))
        c4 = F.relu(self.bn4(self.conv4(x)))
        c5 = F.relu(self.bn5(self.conv5(x)))

        p2 = F.adaptive_max_pool1d(c2, 1).squeeze(-1)
        p3 = F.adaptive_max_pool1d(c3, 1).squeeze(-1)
        p4 = F.adaptive_max_pool1d(c4, 1).squeeze(-1)
        p5 = F.adaptive_max_pool1d(c5, 1).squeeze(-1)

        feat = torch.cat([p2, p3, p4, p5], dim=1)
        h = F.relu(self.fc1(feat))
        h = self.dropout(h)
        logits = self.fc2(h)  # [batch, 2]
        return logits

