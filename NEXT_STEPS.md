# Next Steps (2026-01-30)

1. Complete the Stage 4 SWF pipeline: implement the minimal parser that decompresses only the first 10 tags, enforces the 10:1 ratio/10 MB size and 250 ms timeout guards, and captures ActionScript tag metadata without decoding the whole stream.
2. Wire the rich-media query surface + feature-vector fields (swf, swf.actionscript, media.3d, media.audio, etc.) so the new metadata and detections can be surfaced through the CLI and ML pipelines.
3. Add the remaining SWF/3D/audio unit tests referenced in `plans/20260120-next-analysis-phases.md` (decompression limit, size limit, media detection, query coverage) to prove the extended heuristics before moving into Stage 5.
