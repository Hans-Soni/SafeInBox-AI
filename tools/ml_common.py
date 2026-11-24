"""Common ML Loss Functions, Probability Calibration, and Verification Utilities."""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np


class FocalLoss(nn.Module):
    """Focal Loss with label smoothing and optional class weighting.
    
    FL(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t)
    Down-weights easy examples to focus learning on hard, ambiguous edge-cases.
    """

    def __init__(self, alpha: torch.Tensor | None = None, gamma: float = 2.0, label_smoothing: float = 0.05):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.label_smoothing = label_smoothing

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        ce_loss = F.cross_entropy(
            inputs,
            targets,
            weight=self.alpha,
            label_smoothing=self.label_smoothing,
            reduction='none'
        )
        p = torch.softmax(inputs, dim=1)
        p_t = p.gather(1, targets.unsqueeze(1)).squeeze(1)
        focal_weight = (1.0 - p_t).clamp(min=1e-5, max=1.0) ** self.gamma
        return (focal_weight * ce_loss).mean()


class TemperatureCalibrator(nn.Module):
    """Post-hoc temperature scaling for calibrated posterior probability outputs."""

    def __init__(self):
        super().__init__()
        self.temperature = nn.Parameter(torch.ones(1) * 1.2)

    def forward(self, logits: torch.Tensor) -> torch.Tensor:
        return logits / self.temperature

    def fit(self, val_logits: torch.Tensor, val_labels: torch.Tensor, lr: float = 0.01, max_iter: int = 100):
        """Optimize temperature parameter using NLL on validation set."""
        optimizer = torch.optim.LBFGS([self.temperature], lr=lr, max_iter=max_iter)
        criterion = nn.CrossEntropyLoss()

        def eval_step():
            optimizer.zero_grad()
            scaled = self.forward(val_logits)
            loss = criterion(scaled, val_labels)
            loss.backward()
            return loss

        optimizer.step(eval_step)
        with torch.no_grad():
            self.temperature.clamp_(min=0.5, max=5.0)
        return float(self.temperature.item())
