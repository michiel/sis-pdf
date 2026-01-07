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
import hashlib
from datetime import datetime, timezone
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

CHARS_PER_TOKEN = 4
TAIL_MARKER = " <TAIL> "


def compress_text_for_max_tokens(text: str, max_length: int) -> str:
    max_chars = max_length * CHARS_PER_TOKEN
    if len(text) <= max_chars:
        return text
    if max_chars <= len(TAIL_MARKER) + 2:
        return text[:max_chars]
    head_len = (max_chars - len(TAIL_MARKER)) // 2
    tail_len = max_chars - len(TAIL_MARKER) - head_len
    if tail_len <= 0:
        return text[:max_chars]
    return f"{text[:head_len]}{TAIL_MARKER}{text[-tail_len:]}"


def serialize_ir_line(line: dict, index: int) -> str:
    path = line.get("path", "")
    value_type = line.get("type", "")
    value = line.get("value", "")
    obj_ref = line.get("obj", "")
    line_index = line.get("line_index", index)
    return (
        f"path={path}\tvalue_type={value_type}\tvalue={value}"
        f"\tobj={obj_ref}\tline_index={line_index}"
    )


def serialize_ir_object(obj: dict) -> str:
    lines = obj.get("lines", [])
    pieces = [serialize_ir_line(line, idx) for idx, line in enumerate(lines)]
    deviations = obj.get("deviations", [])
    if deviations:
        pieces.append(
            f"path=$meta\tvalue_type=deviation\tvalue={','.join(deviations)}"
        )
    return " ; ".join(pieces)


def load_sample(ir_path: Path, org_path: Path):
    ir = json.loads(ir_path.read_text())
    org = json.loads(org_path.read_text())

    node_texts = []
    node_ids = {}
    for idx, obj in enumerate(ir.get("objects", [])):
        node_texts.append(serialize_ir_object(obj))
        if "obj" in obj:
            node_ids[obj["obj"]] = idx
    if not node_texts:
        print(f"warning: {ir_path} has no objects; using placeholder node")
        node_texts = ["/EMPTY"]

    edge_index = []
    sentinel_idx = None
    unresolved_edges = 0
    for edge in org.get("edges", []):
        # Accept both "src/dst" and "from/to" edge formats.
        if "src" in edge and "dst" in edge:
            src, dst = edge["src"], edge["dst"]
        else:
            src, dst = edge["from"], edge["to"]
        src_idx = node_ids.get(src)
        dst_idx = node_ids.get(dst)
        if src_idx is None or dst_idx is None:
            unresolved_edges += 1
            if sentinel_idx is None:
                sentinel_idx = len(node_texts)
                node_texts.append(
                    "path=$meta\tvalue_type=unresolved_edges\tvalue=1"
                )
            if src_idx is None:
                src_idx = sentinel_idx
            if dst_idx is None:
                dst_idx = sentinel_idx
        edge_index.append((src_idx, dst_idx))

    if unresolved_edges:
        print(
            f"warning: {org_path} has {unresolved_edges} edges that don't resolve to IR nodes"
        )
    if unresolved_edges and sentinel_idx is not None:
        node_texts[sentinel_idx] = (
            f"path=$meta\tvalue_type=unresolved_edges\tvalue={unresolved_edges}"
        )

    if not edge_index and node_texts:
        node_texts[0] = f"{node_texts[0]} ; path=$meta\tvalue_type=edge_count\tvalue=0"

    return node_texts, edge_index


def build_dataset(manifest_path: Path):
    dataset = []
    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        node_texts, edge_index = load_sample(Path(item["ir"]), Path(item["org"]))
        label_value = item.get("label")
        if label_value == "malicious":
            label = 1
        elif label_value == "benign":
            label = 0
        else:
            raise RuntimeError(f"Unsupported label: {label_value}")
        dataset.append((node_texts, edge_index, label))
    if not dataset:
        raise RuntimeError(f"No samples found in manifest: {manifest_path}")
    return dataset


def embed_texts(
    tokenizer,
    model,
    texts,
    device,
    batch_size=32,
    max_length=256,
    pooling="cls",
):
    model.eval()
    outputs = []
    batches = range(0, len(texts), batch_size)
    if tqdm:
        batches = tqdm(batches, desc="embedding", unit="batch")
    for i in batches:
        chunk = [
            compress_text_for_max_tokens(text, max_length)
            for text in texts[i : i + batch_size]
        ]
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
        last_hidden = out.last_hidden_state
        if pooling == "mean":
            mask = batch["attention_mask"].unsqueeze(-1).to(last_hidden.dtype)
            masked = last_hidden * mask
            summed = masked.sum(dim=1)
            denom = mask.sum(dim=1).clamp(min=1.0)
            pooled = summed / denom
        else:
            pooled = last_hidden[:, 0, :]
        outputs.append(pooled.cpu())
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


def export_onnx(
    encoder, tokenizer, gnn_model, out_dir: Path, device, opset_version, pooling
):
    out_dir.mkdir(parents=True, exist_ok=True)

    class EncoderWithPooling(nn.Module):
        def __init__(self, model, pooling):
            super().__init__()
            self.model = model
            self.pooling = pooling

        def forward(self, input_ids, attention_mask, token_type_ids=None):
            if token_type_ids is None:
                out = self.model(input_ids=input_ids, attention_mask=attention_mask)
            else:
                out = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    token_type_ids=token_type_ids,
                )
            last_hidden = out.last_hidden_state
            if self.pooling == "mean":
                mask = attention_mask.unsqueeze(-1).to(last_hidden.dtype)
                summed = (last_hidden * mask).sum(dim=1)
                denom = mask.sum(dim=1).clamp(min=1.0)
                return summed / denom
            return last_hidden[:, 0, :]

    dummy = tokenizer(["/Type /Page"], return_tensors="pt")
    dummy = {k: v.to(device) for k, v in dummy.items()}
    embed_inputs = [dummy["input_ids"], dummy["attention_mask"]]
    embed_names = ["input_ids", "attention_mask"]
    embed_dynamic_axes = {
        "input_ids": {0: "batch", 1: "seq"},
        "attention_mask": {0: "batch", 1: "seq"},
    }
    if "token_type_ids" in dummy:
        embed_inputs.append(dummy["token_type_ids"])
        embed_names.append("token_type_ids")
        embed_dynamic_axes["token_type_ids"] = {0: "batch", 1: "seq"}

    pooled_encoder = EncoderWithPooling(encoder, pooling=pooling)

    torch.onnx.export(
        pooled_encoder,
        tuple(embed_inputs),
        str(out_dir / "embedding.onnx"),
        input_names=embed_names,
        output_names=["pooled_embedding"],
        dynamic_axes={**embed_dynamic_axes, "pooled_embedding": {0: "batch"}},
        opset_version=opset_version,
        dynamo=False,
    )

    dummy_x = torch.randn(10, gnn_model.conv1.nn[0].in_features, device=device)
    dummy_edge_index = torch.zeros(2, 10, dtype=torch.long, device=device)
    class GnnWrapper(nn.Module):
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
        opset_version=opset_version,
        dynamo=False,
    )


def write_tokenizer(tokenizer, out_dir: Path):
    if not hasattr(tokenizer, "backend_tokenizer"):
        raise RuntimeError("Tokenizer is not a fast tokenizer; cannot save tokenizer.json")
    tokenizer.backend_tokenizer.save(str(out_dir / "tokenizer.json"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_graph_model_config(
    out_dir: Path,
    model_name: str,
    output_dim: int,
    max_length: int,
    pooling: str,
    embedding_input_names: dict,
):
    embedding_path = out_dir / "embedding.onnx"
    graph_path = out_dir / "graph.onnx"
    tokenizer_path = out_dir / "tokenizer.json"
    graph_model = {
        "schema_version": 1,
        "name": f"pdfobj2vec_{model_name.replace('/', '_')}",
        "version": "1.0.0",
        "embedding": {
            "backend": "onnx",
            "model_path": "embedding.onnx",
            "tokenizer_path": "tokenizer.json",
            "max_length": max_length,
            "pooling": pooling,
            "output_dim": output_dim,
            "input_names": embedding_input_names,
            "output_name": "pooled_embedding",
            "normalize": {
                "normalize_numbers": True,
                "normalize_strings": True,
                "collapse_obj_refs": True,
                "preserve_keywords": [
                    "/JS",
                    "/JavaScript",
                    "/OpenAction",
                    "/AA",
                    "/Launch",
                    "/GoToR",
                    "/URI",
                    "/SubmitForm",
                    "/RichMedia",
                    "/EmbeddedFile",
                    "/ObjStm",
                ],
                "hash_strings": True,
                "include_deviation_markers": True,
            },
        },
        "graph": {
            "backend": "onnx",
            "model_path": "graph.onnx",
            "input_dim": output_dim,
            "output_name": "graph_score",
            "node_scores_name": "node_scores",
            "output": {"kind": "logit", "apply_sigmoid": True},
        },
        "threshold": 0.9,
        "edge_index": {"directed": True, "add_reverse_edges": True},
        "integrity": {
            "embedding_sha256": sha256_file(embedding_path),
            "graph_sha256": sha256_file(graph_path),
            "tokenizer_sha256": sha256_file(tokenizer_path),
        },
    }
    (out_dir / "graph_model.json").write_text(
        json.dumps(graph_model, indent=2) + "\n"
    )


def write_metadata(
    out_dir: Path,
    manifest_path: Path,
    model_name: str,
    opset_version: int,
    output_dim: int,
    max_length: int,
    counts: dict,
):
    def size_of(name):
        path = out_dir / name
        return path.stat().st_size if path.exists() else None

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "manifest": str(manifest_path),
            "samples": counts,
        },
        "model": {
            "encoder": model_name,
            "embedding_output_dim": output_dim,
            "max_length": max_length,
            "graph_opset": opset_version,
        },
        "artifacts": {
            "embedding.onnx": {
                "bytes": size_of("embedding.onnx"),
                "sha256": sha256_file(out_dir / "embedding.onnx"),
            },
            "graph.onnx": {
                "bytes": size_of("graph.onnx"),
                "sha256": sha256_file(out_dir / "graph.onnx"),
            },
            "tokenizer.json": {
                "bytes": size_of("tokenizer.json"),
                "sha256": sha256_file(out_dir / "tokenizer.json"),
            },
            "graph_model.json": {
                "bytes": size_of("graph_model.json"),
                "sha256": sha256_file(out_dir / "graph_model.json"),
            },
        },
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, help="Path to dataset.jsonl")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--model", default="bert-base-uncased", help="HF encoder name")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--pooling", default="cls", choices=["cls", "mean"])
    parser.add_argument("--onnx-opset", type=int, default=18)
    parser.add_argument(
        "--allow-experimental-sdpa",
        action="store_true",
        help="Enable ROCm experimental Flash/Mem Efficient SDPA kernels.",
    )
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    rocm_version = getattr(torch.version, "hip", None)
    cuda_version = torch.version.cuda
    backend = "rocm" if rocm_version else ("cuda" if cuda_version else "cpu")
    version_tag = rocm_version or cuda_version or "n/a"
    print(f"using device: {device} (backend={backend} version={version_tag})")
    configure_sdp(device, args.allow_experimental_sdpa)

    dataset = build_dataset(Path(args.manifest))
    tokenizer = AutoTokenizer.from_pretrained(args.model, use_fast=True)
    encoder = AutoModel.from_pretrained(args.model).to(device)

    graphs = []
    graph_iter = dataset
    if tqdm:
        graph_iter = tqdm(dataset, desc="building graphs", unit="graph")
    for node_texts, edge_index, label in graph_iter:
        node_features = embed_texts(
            tokenizer,
            encoder,
            node_texts,
            device,
            batch_size=args.batch_size,
            max_length=args.max_length,
            pooling=args.pooling,
        )
        graphs.append(build_graph_data(node_features, edge_index, label))

    if not graphs:
        raise RuntimeError("No graphs constructed from dataset; check input data.")
    in_dim = graphs[0].x.shape[1]
    gnn_model = train_gnn(graphs, in_dim, device, epochs=args.epochs)
    export_onnx(
        encoder,
        tokenizer,
        gnn_model,
        Path(args.out),
        device,
        args.onnx_opset,
        args.pooling,
    )
    out_dir = Path(args.out)
    write_tokenizer(tokenizer, out_dir)
    has_token_type = (
        tokenizer.model_input_names
        and "token_type_ids" in tokenizer.model_input_names
    )
    embedding_input_names = {
        "input_ids": "input_ids",
        "attention_mask": "attention_mask",
        "token_type_ids": "token_type_ids" if has_token_type else None,
    }
    write_graph_model_config(
        out_dir,
        args.model,
        in_dim,
        max_length=args.max_length,
        pooling=args.pooling,
        embedding_input_names=embedding_input_names,
    )
    counts = {
        "total": len(dataset),
        "malicious": sum(1 for _, _, label in dataset if label == 1),
        "benign": sum(1 for _, _, label in dataset if label == 0),
    }
    write_metadata(
        out_dir,
        Path(args.manifest),
        args.model,
        args.onnx_opset,
        in_dim,
        args.max_length,
        counts,
    )


if __name__ == "__main__":
    main()
