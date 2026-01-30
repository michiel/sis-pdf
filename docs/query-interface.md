# Query Interface Guide

This guide describes the `sis query` interface for exploring PDF structure, content, and findings.

## Basics

Run a one-shot query:

```bash
sis query sample.pdf images
```

Start an interactive REPL:

```bash
sis query sample.pdf
```

## Common Queries

```bash
sis query sample.pdf pages
sis query sample.pdf js.count
sis query sample.pdf embedded
sis query sample.pdf images
sis query sample.pdf images.risky
sis query sample.pdf launch
sis query sample.pdf embedded.executables
sis query sample.pdf embedded.executables.count
sis query sample.pdf xfa.submit
sis query sample.pdf filters.unusual
sis query sample.pdf streams.high-entropy
sis query sample.pdf streams.entropy
sis query sample.pdf xfa.scripts.count
sis query sample.pdf swf.count
sis query sample.pdf swf.actionscript
sis query sample.pdf media.3d
sis query sample.pdf media.audio
sis query sample.pdf encryption
sis query sample.pdf encryption.weak
sis query sample.pdf encryption.weak.count
```

## Image Queries

Image queries report image XObjects and XFA images:

```bash
sis query sample.pdf images
sis query sample.pdf images.jbig2
sis query sample.pdf images.jpx
sis query sample.pdf images.ccitt
sis query sample.pdf images.risky
sis query sample.pdf images.malformed --deep
```

## Rich media queries

Use `swf` and `swf.actionscript` to list all SWF streams or just the ones that carry ActionScript tags; `media.3d` and `media.audio` summarise 3D, visual and audio/rendition objects, and all four commands grow richer metadata with each scan. They support `--where` filters on SWF version, action-tag count, declared size, media type and payload size.

```bash
sis query sample.pdf swf --where "size > 1024"
sis query sample.pdf swf.actionscript --format json
sis query sample.pdf media.3d --where "media_type == 'prc'"
sis query sample.pdf media.audio --where "media_type == 'mp3'"
```

## Predicate Filters

Use `--where` to filter results:

```bash
sis query sample.pdf images --where "pixels > 1000000 AND risky == true"
sis query sample.pdf images --where "format == 'PNG' AND entropy > 7.5"
sis query sample.pdf findings.count --where "subtype == 'embedded_executable_present'"
```

See `docs/query-predicates.md` for all fields.

## Extraction

Extract payloads to disk:

```bash
sis query sample.pdf images --extract-to /tmp/images
sis query sample.pdf images --extract-to /tmp/images --raw
sis query sample.pdf xfa.scripts --extract-to /tmp/xfa-scripts
sis query sample.pdf swf --extract-to /tmp/swf --decode
sis query sample.pdf swf.extract --extract-to /tmp/swf
sis query sample.pdf stream 1487 0 --extract-to /tmp/streams --decode
```

When `stream` is used without `--extract-to`, it returns a short preview string instead of writing a file.

## Output Formats

```bash
sis query sample.pdf images --format json
sis query sample.pdf images --format jsonl
sis query sample.pdf images --format yaml
sis query sample.pdf images --format json --colour
```

## Finding Shortcuts

The following query shortcuts return `findings.kind` for common analysis paths.
Add `.count` to return a numeric count.

```bash
sis query sample.pdf embedded.executables
sis query sample.pdf embedded.scripts
sis query sample.pdf embedded.archives.encrypted
sis query sample.pdf embedded.encrypted
sis query sample.pdf launch
sis query sample.pdf launch.external
sis query sample.pdf launch.embedded
sis query sample.pdf actions.chains.complex
sis query sample.pdf actions.triggers.automatic
sis query sample.pdf actions.triggers.hidden
sis query sample.pdf xfa.submit
sis query sample.pdf xfa.sensitive
sis query sample.pdf xfa.too-large
sis query sample.pdf xfa.scripts.high
sis query sample.pdf findings.swf
sis query sample.pdf streams.high-entropy
sis query sample.pdf streams.entropy
sis query sample.pdf encryption
sis query sample.pdf encryption.weak
sis query sample.pdf encryption.weak.count
sis query sample.pdf filters.unusual
sis query sample.pdf filters.invalid
sis query sample.pdf filters.repeated
sis query sample.pdf findings.composite
sis query sample.pdf findings.composite.count
```

## Action Chain Queries

Use `actions.chains` to inspect the catalog of action chains and `actions.chains.count` to tally them (predicate filtering applies to both). The JSON output includes chain metadata such as trigger, length (depth), automatic flag, `has_js`, and `has_external` flags, so you can run queries like:

```bash
sis query sample.pdf actions.chains
sis query sample.pdf actions.chains.count
sis query sample.pdf actions.chains --where "depth >= 3"
sis query sample.pdf actions.chains --where "has_js == true"
sis query sample.pdf actions.chains --format json
```

`actions.chains` also supports the `--format dot` export that can be rendered with Graphviz.

## XFA form queries

`xfa`/`xfa.count` lists decoded XFA payloads with script counts, submit targets, and hidden-field indicators. Use `--where` to filter by payload size or script volume, and predicate filtering extends to `xfa.submit`/`xfa.sensitive` via the `url` and `field` fields.

```bash
sis query sample.pdf xfa
sis query sample.pdf xfa.count
sis query sample.pdf xfa --where "size > 500000"
sis query sample.pdf xfa --where "script_count > 5"
sis query sample.pdf xfa.submit --where "url contains 'external.com'"
```

## Encryption & Stream Entropy Queries

`encryption` reports findings related to `/Encrypt` dictionaries, including detected algorithms and key lengths. Use `encryption.weak` to focus on detected weak cryptography and `.count` to tally them.

```bash
sis query sample.pdf encryption
sis query sample.pdf encryption.weak --where "crypto.algorithm == 'RC4-40'"
sis query sample.pdf encryption.weak.count
```

`streams.entropy` lists every decoded stream along with entropy, sample size, magic type, and timing metadata. Combine with `--where` to hunt for highly entropic, unknown, or timed-out streams.

```bash
sis query sample.pdf streams.entropy --where "entropy > 7.5 AND magic == 'unknown'"
sis query sample.pdf streams.entropy --format jsonl
```

## Filter Chain Queries

Inspect filter-chain findings with optional predicates:

```bash
sis query sample.pdf filters.unusual
sis query sample.pdf filters.invalid
sis query sample.pdf filters.repeated
sis query sample.pdf filters.unusual --where "filter_count > 1"
sis query sample.pdf filters.invalid --where "violation_type == 'crypt_not_outermost'"
```
