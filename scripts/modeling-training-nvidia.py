#!/usr/bin/env python3
"""Minimal end-to-end training pipeline for SIS-PDF graph ML (NVIDIA).

Requires (install with pip):
  pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
  pip install transformers tokenizers
  pip install torch-geometric torch-scatter torch-sparse torch-cluster torch-spline-conv \
    -f https://data.pyg.org/whl/torch-2.4.0+cu121.html
  pip install onnx

Notes:
- Adjust CUDA/PyTorch versions to match your system.
- This script expects IR and ORG JSON files exported by sis-pdf.
- It trains a simple GIN and exports encoder + GNN to ONNX.
"""

import argparse
import json
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, AutoModel
from torch_geometric.data import Data
from torch_geometric.nn import GINConv, global_add_pool


def load_sample(ir_path: Path, org_path: Path):
    ir = json.loads(ir_path.read_text())
    org = json.loads(org_path.read_text())

    node_texts = []
    for obj in ir["objects"]:
        lines = []
        for line in obj["lines"]:
            lines.append(f'{line["path"]} {line["type"]} {line["value"]}')
        node_texts.append(" ; ".join(lines))

    edge_index = []
    for edge in org.get("edges", []):
        edge_index.append((edge["src"], edge["dst"]))

    return node_texts, edge_index


def build_dataset(manifest_path: Path):
    dataset = []
    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        node_texts, edge_index = load_sample(Path(item["ir"]), Path(item["org"]))
        label = 1 if item["label"] == "malicious" else 0
        dataset.append((node_texts, edge_index, label))
    return dataset


def embed_texts(tokenizer, model, texts, device, batch_size=32, max_length=256):
    model.eval()
    outputs = []
    for i in range(0, len(texts), batch_size):
        chunk = texts[i : i + batch_size]
        batch = tokenizer(
            chunk,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.no_grad():
            out = model(**batch)
        outputs.append(out.last_hidden_state[:, 0, :].cpu())
    return torch.cat(outputs, dim=0)


class GIN(nn.Module):
    def __init__(self, in_dim, hidden_dim):
        super().__init__()
        self.conv1 = GINConv(
            nn.Sequential(
                nn.Linear(in_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
            )
        )
        self.node_head = nn.Linear(hidden_dim, 1)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        node_logits = self.node_head(x)
        graph_logit = global_add_pool(node_logits, batch)
        return graph_logit, node_logits


def build_graph_data(node_features, edge_index, label):
    if len(edge_index) == 0:
        edge_index = [(0, 0)]
    edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    return Data(x=node_features, edge_index=edge_index, y=torch.tensor([label]))


def train_gnn(graphs, in_dim, device, epochs=5):
    model = GIN(in_dim, 128).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.BCEWithLogitsLoss()

    loader = DataLoader(graphs, batch_size=8, shuffle=True)
    model.train()
    for epoch in range(epochs):
        total = 0.0
        for batch in loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            graph_logits, _ = model(batch.x, batch.edge_index, batch.batch)
            loss = loss_fn(graph_logits.view(-1), batch.y.float().to(device))
            loss.backward()
            optimizer.step()
            total += loss.item()
        print(f"epoch {epoch+1}: loss={total:.4f}")
    return model


def export_onnx(encoder, tokenizer, gnn_model, out_dir: Path, device):
    out_dir.mkdir(parents=True, exist_ok=True)

    dummy = tokenizer(["/Type /Page"], return_tensors="pt")
    dummy = {k: v.to(device) for k, v in dummy.items()}

    torch.onnx.export(
        encoder,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(out_dir / "embedding.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["last_hidden_state"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
        },
        opset_version=17,
    )

    dummy_x = torch.randn(10, gnn_model.conv1.nn[0].in_features, device=device)
    dummy_edge_index = torch.zeros(2, 10, dtype=torch.long, device=device)
    class GnnWrapper(torch.nn.Module):
        def __init__(self, gnn):
            super().__init__()
            self.gnn = gnn

        def forward(self, x, edge_index):
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
            graph_logit, node_logits = self.gnn(x, edge_index, batch)
            return graph_logit, node_logits.squeeze(-1)

    wrapper = GnnWrapper(gnn_model)
    torch.onnx.export(
        wrapper,
        (dummy_x, dummy_edge_index),
        str(out_dir / "graph.onnx"),
        input_names=["node_features", "edge_index"],
        output_names=["graph_score", "node_scores"],
        dynamic_axes={
            "node_features": {0: "num_nodes"},
            "edge_index": {1: "num_edges"},
            "graph_score": {0: "batch"},
            "node_scores": {0: "num_nodes"},
        },
        opset_version=17,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, help="Path to dataset.jsonl")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--model", default="bert-base-uncased", help="HF encoder name")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"using device: {device}")

    dataset = build_dataset(Path(args.manifest))
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    encoder = AutoModel.from_pretrained(args.model).to(device)

    graphs = []
    for node_texts, edge_index, label in dataset:
        node_features = embed_texts(
            tokenizer, encoder, node_texts, device, batch_size=args.batch_size
        )
        graphs.append(build_graph_data(node_features, edge_index, label))

    gnn_model = train_gnn(graphs, node_features.shape[1], device, epochs=args.epochs)
    export_onnx(encoder, tokenizer, gnn_model, Path(args.out), device)


if __name__ == "__main__":
    main()
