#!/usr/bin/env python3
"""Minimal end-to-end training pipeline for SIS-PDF graph ML.

Requires (install with pip):
  pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.1
  pip install transformers tokenizers
  pip install torch-geometric torch-scatter torch-sparse torch-cluster torch-spline-conv \
    -f https://data.pyg.org/whl/torch-2.4.0+rocm6.1.html
  pip install onnx

Notes:
- Adjust ROCm/PyTorch versions to match your system.
- This script expects IR and ORG JSON files exported by sis-pdf.
- It trains a simple GIN and exports encoder + GNN to ONNX.
"""

import argparse
import json
from pathlib import Path

import torch
import torch.nn as nn
from torch_geometric.loader import DataLoader
from transformers import AutoTokenizer, AutoModel
from torch_geometric.data import Data
from torch_geometric.nn import GINConv, global_add_pool
try:
    from tqdm import tqdm
except ImportError:  # Optional dependency.
    tqdm = None


def load_sample(ir_path: Path, org_path: Path):
    ir = json.loads(ir_path.read_text())
    org = json.loads(org_path.read_text())

    node_texts = []
    node_ids = {}
    for idx, obj in enumerate(ir.get("objects", [])):
        lines = []
        for line in obj.get("lines", []):
            path = line.get("path", "")
            line_type = line.get("type", "")
            value = line.get("value", "")
            lines.append(f"{path} {line_type} {value}".strip())
        node_texts.append(" ; ".join(lines))
        if "obj" in obj:
            node_ids[obj["obj"]] = idx
    if not node_texts:
        print(f"warning: {ir_path} has no objects; using placeholder node")
        node_texts = ["/EMPTY"]

    edge_index = []
    unresolved = 0
    for edge in org.get("edges", []):
        # Accept both "src/dst" and "from/to" edge formats.
        if "src" in edge and "dst" in edge:
            src, dst = edge["src"], edge["dst"]
        else:
            src, dst = edge["from"], edge["to"]
        if src in node_ids and dst in node_ids:
            edge_index.append((node_ids[src], node_ids[dst]))
        else:
            unresolved += 1

    if unresolved:
        print(
            f"warning: {org_path} has {unresolved} edges that don't resolve to IR nodes"
        )

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
    if not dataset:
        raise RuntimeError(f"No samples found in manifest: {manifest_path}")
    return dataset


def embed_texts(tokenizer, model, texts, device, batch_size=32, max_length=256):
    model.eval()
    outputs = []
    batches = range(0, len(texts), batch_size)
    if tqdm:
        batches = tqdm(batches, desc="embedding", unit="batch")
    for i in batches:
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
        self.lin = nn.Linear(hidden_dim, 1)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = global_add_pool(x, batch)
        return self.lin(x)


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
            logits = model(batch.x, batch.edge_index, batch.batch)
            loss = loss_fn(logits.view(-1), batch.y.float().to(device))
            loss.backward()
            optimizer.step()
            total += loss.item()
        print(f"epoch {epoch+1}: loss={total:.4f}")
    return model


def configure_sdp(device, allow_experimental):
    if device.type != "cuda":
        return
    if not hasattr(torch.backends, "cuda"):
        return
    # Avoid ROCm experimental Flash/Mem Efficient SDPA warnings by default.
    if allow_experimental:
        settings = (
            ("enable_flash_sdp", True),
            ("enable_mem_efficient_sdp", True),
            ("enable_math_sdp", True),
        )
    else:
        settings = (
            ("enable_flash_sdp", False),
            ("enable_mem_efficient_sdp", False),
            ("enable_math_sdp", True),
        )
    for name, value in settings:
        fn = getattr(torch.backends.cuda, name, None)
        if callable(fn):
            fn(value)


def export_onnx(encoder, tokenizer, gnn_model, out_dir: Path, device, opset_version):
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
        opset_version=opset_version,
        dynamo=False,
    )

    dummy_x = torch.randn(10, gnn_model.conv1.nn[0].in_features, device=device)
    dummy_edge_index = torch.zeros(2, 10, dtype=torch.long, device=device)
    dummy_batch = torch.zeros(10, dtype=torch.long, device=device)

    torch.onnx.export(
        gnn_model,
        (dummy_x, dummy_edge_index, dummy_batch),
        str(out_dir / "graph.onnx"),
        input_names=["node_features", "edge_index", "batch"],
        output_names=["score"],
        opset_version=opset_version,
        dynamo=False,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, help="Path to dataset.jsonl")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--model", default="bert-base-uncased", help="HF encoder name")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--onnx-opset", type=int, default=18)
    parser.add_argument(
        "--allow-experimental-sdpa",
        action="store_true",
        help="Enable ROCm experimental Flash/Mem Efficient SDPA kernels.",
    )
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"using device: {device}")
    configure_sdp(device, args.allow_experimental_sdpa)

    dataset = build_dataset(Path(args.manifest))
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    encoder = AutoModel.from_pretrained(args.model).to(device)

    graphs = []
    graph_iter = dataset
    if tqdm:
        graph_iter = tqdm(dataset, desc="building graphs", unit="graph")
    for node_texts, edge_index, label in graph_iter:
        node_features = embed_texts(
            tokenizer, encoder, node_texts, device, batch_size=args.batch_size
        )
        graphs.append(build_graph_data(node_features, edge_index, label))

    if not graphs:
        raise RuntimeError("No graphs constructed from dataset; check input data.")
    in_dim = graphs[0].x.shape[1]
    gnn_model = train_gnn(graphs, in_dim, device, epochs=args.epochs)
    export_onnx(encoder, tokenizer, gnn_model, Path(args.out), device, args.onnx_opset)


if __name__ == "__main__":
    main()
