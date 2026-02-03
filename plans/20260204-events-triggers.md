# 20260204 Event trigger coverage plan

## Context

`sis query ... events` currently enumerates document-, page-, and field-level triggers by walking the catalog tree, page dictionaries, and form widgets. After the rewrite to prefer the “final” trailer we now iterate the trailers list in reverse, so we actually stop at the *earliest* `/Root`, and synthetic fixtures with `/OpenAction` in the latest catalog still return no events. The findings table still shows `open_action_present`, so the detectors are aware of the trigger; the events query needs to overtake the same knowledge.

## Goals

1. Always use the **latest catalog** (`/Root` entry) as the source for document-level triggers, but still fall back to earlier trailers when no `/Root` is present.
2. Keep the traversal limited to actual triggers: only emit Doc/Page/Field events when the corresponding dictionaries contain `/OpenAction`, `AA`, annotation `/A`, or field actions that are reachable through the catalog hierarchy.
3. Document and test the new behaviour so we know `events` always reflects the triggers that are actually executable in the parsed PDF.

## Implementation steps

1. Add a helper (e.g. `find_latest_catalog`) that iterates `ctx.graph.trailers` from index 0 (newest) forward, returning the first `/Root` it finds. If none is present there, fall back to earlier trailers. This ensures we look at the most recent catalog before breaking.
2. Because the CLI parser may still yield `graph.trailers` that are empty (some corpora have malformed `startxref` pointers), extend `find_latest_catalog` to scan `ctx.graph.objects` in reverse for a dictionary whose `/Type` is `/Catalog`. This fallback guarantees we can still build document events even when trailers are missing.
3. Update `extract_event_triggers` to call `find_latest_catalog` and use its catalog dict for the document-level events, rather than looping on an inverse trailer order, so document OpenAction/AA events appear even when we rely on the fallback catalog.
4. Keep the page/field loops unchanged: they already iterate every page and widget to emit their events (but mark events with the level string so filters can drop unrelated ones if needed).
5. Add a lightweight unit test for `find_latest_catalog` that covers both the trailer-based path and the object fallback. Construct a synthetic `ObjectGraph` with and without trailers and ensure we always return the catalog dict we expect.
6. Add another regression test exercising `extract_event_triggers` against a fake catalog (with `/OpenAction`) but no trailers so we make sure the document-level event still appears.
7. Verify manually (and via existing tests) that `events` now yields the OpenAction doc event for `tmp/synthetic.pdf` and similar fixtures.
