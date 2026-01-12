## Findings
- High: `list_page_cycles` still walks every outgoing reference once it reaches a Page/Pages object, so unrelated graph cycles can appear in the page-cycle output; the traversal should restrict itself to `/Kids` and `/Parent` edge types.
- Medium: `find_cycles_dfs` currently marks nodes as permanently visited, which can hide additional cycles inside the same connected component if there are multiple loops.
- Medium: Regression coverage only exercises the JSON helpers; no PDF fixtures currently drive the `chains`, `chains.js`, `cycles`, or `cycles.page` queries via the CLI or public API.
- Low: `plans/20260112-query-implementation-summary.md` still lists the advanced queries as unfinished, even though JSON-rich versions now exist and the REPL help advertises them.

## Open Questions
1. Should `cycles.page` be limited to page-tree edges (`/Kids` and `/Parent`), or is it acceptable to follow every reference from Page/Pages nodes if the cycle is ultimately rooted there?
2. Are there more structured export modes (DOT, graph JSON) we want to plug in now, or should we keep the existing `QueryResult::Structure` JSON body for the short term?
3. What additional metadata (risk score, payload type, path length) should the `chains` / `chains.js` JSON objects expose to users?

## Change Summary
- Advanced queries now emit structured JSON via `QueryResult::Structure`, with `chains`/`chains.js` returning per-chain edge lists, trigger metadata, payload references, and risk scoring.
- The REPL help text was extended to list all advanced queries plus `findings.critical`, and `chains.js` now filters to JavaScript chains while retaining the richer detail set.
- Added unit tests covering `chain_to_json` and `cycle_to_json`, along with the helpers that build the JSON payloads for these queries.

## Next Steps
1. Restrict `cycles.page` traversal to `/Kids` and `/Parent` edges (and allow revisiting nodes in the same component) so that only genuine page-tree loops are reported.
2. Add regression fixtures or integration tests that execute `sis query chains`, `sis query chains.js`, `sis query cycles`, and `sis query cycles.page` to confirm the JSON output surface.
3. Refresh `plans/20260112-query-implementation-summary.md` (and any documentation referencing advanced queries) to describe the current JSON-enabled behavior.
