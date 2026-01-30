# ML Feature Vector Reference

The `sis` feature extraction pipeline produces a fixed-length 81-element vector that feeds ML models and inference tooling. Each feature is available through the `sis query features` command, the CSV/JSON exports and the streaming JSONL output (`--format jsonl`). The order is stable; indexes run from **0** to **80** and are guaranteed to match `sis_pdf_core::features::feature_names()` and `FeatureVector::as_f32_vec()`.

## Viewing the feature vector

Use `sis` directly to inspect the vector for a PDF:

```bash
sis query sample.pdf features --format csv > sample-features.csv
sis query sample.pdf features --format json | jq -r '.features'
sis query --path corpus --glob "*.pdf" features --format jsonl
```

In code or ML pipelines, treat missing content (e.g., no XFA) as zeros. The vector is dense and append-only: new feature groups appear at the end of the vector to preserve compatibility.

## Feature categories and index mapping

| Category | Index range | Description | Example fields | Type hints |
| --- | --- | --- | --- | --- |
| **General (0–3)** | 0‑3 | File size, entropy, binary/text ratio and object count | `general.file_size`, `general.object_count` | Numeric; counts / ratios |
| **Structural (4–8)** | 4‑8 | XRef layout metrics | `structural.startxref_count`, `structural.linearized_present` | Counts / boolean |
| **Behavioural (9–15)** | 9‑15 | Action/JS activity counts and averages | `behavior.action_count`, `behavior.js_entropy_avg` | Counts / averages |
| **Content (16–20)** | 16‑20 | Top-level embedded/rich-media/annotation counts | `content.embedded_file_count`, `content.page_count` | Counts |
| **Graph (20–34)** | 20‑34 | Typed graph statistics, chain depth, and trigger mix | `graph.total_edges`, `graph.action_chain_count`, `graph.hidden_trigger_count`, `graph.user_trigger_count`, `graph.complex_chain_count` | Counts / lengths |
| **Images (35–50)** | 35‑50 | Image format counts, size, entropy and decoding anomalies (JBIG2, JPX, CCITT, malformed, extreme dimensions, multi-filter usage, XFA image count) | `images.jbig2_count`, `images.max_image_pixels`, `images.malformed_image_count` | Counts, pixels, entropy averages |
| **Additional content (51–62)** | 51‑62 | Embedded executable/script/archive/double-extension/encrypted counts plus detailed rich media breakdown (SWF, action script and media format totals) | `content.embedded_executable_count`, `content.rich_media_swf_count`, `content.swf_count`, `content.swf_actionscript_count`, `content.media_audio_count`, `content.media_video_count` | Counts |
| **XFA (58–63)** | 58‑63 | Form payload/script/submit/sensitive-field metrics | `xfa.present`, `xfa.script_count`, `xfa.max_payload_bytes` | Binary flag + counts/sizes |
| **Encryption (64–70)** | 64‑70 | Encryption dictionary presence, key length, entropy statistics, and encrypted embedded files | `encryption.encrypted`, `encryption.encryption_key_length`, `encryption.high_entropy_stream_count`, `encryption.avg_stream_entropy`, `encryption.max_stream_entropy`, `encryption.encrypted_embedded_file_count` | Flags, counts, entropy |
| **Filters (71–75)** | 71‑75 | Filter chain anomalies (counts, max depth, unusual/invalid/duplicate patterns) | `filters.unusual_chain_count`, `filters.duplicate_filter_count` | Counts |

## Feature types and normalisation guidance

- **Counts** (e.g., `image_count`, `filters.filter_chain_count`) are integer accumulation values; normalise them per page count or document size if your model expects scaled inputs.
- **Ratios/averages** (e.g., `general.binary_ratio`, `graph.avg_graph_depth`, `images.avg_image_entropy`) are already bounded between 0‑1 or by plausible maxima. Clamp values if your ML model assumes smaller ranges.
- **Booleans** (e.g., `structural.linearized_present`, `encryption.encrypted`) are encoded as `1.0` (true) or `0.0` (false) inside the vector.
- **Entropy and pixels** can be large; use log-scaling when training on feature vectors from very large collections to avoid dominance by outliers.

## ML integration example

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

features = pd.read_csv('features.csv')
x = features.iloc[:, :76].values
labels = pd.read_csv('labels.csv')['malicious'].values
model = RandomForestClassifier(n_estimators=200)
model.fit(x, labels)
```

The CSV/JSON exports include the header row (`feature_names()`) so the columns align with the index mapping above.

## Stability guarantees

- The feature vector order is deterministic and only extends at the end; existing indexes will never shift backward.
- Feature names live in `sis_pdf_core::features::feature_names()` and are re-exported via `sis query features --format json`.
- Flags such as `--ml-config` or `sis query --format csv` must always refer to the `sis` binary when documenting commands.

## Troubleshooting

- Missing feature columns (e.g., no XFA) show up as zero-filled entries in the CSV/JSON exports.
- Run `sis query features --format jsonl --path corpus --glob "*.pdf"` for streaming ingestion in ML pipelines.
- Use `sis query features --where "general.file_size > 1000000"` to filter by messages tied to the feature vector output.
