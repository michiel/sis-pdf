#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_findings(path: Path):
    kinds_by_path = defaultdict(set)
    counts = Counter()
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            finding = rec.get("finding")
            if not finding:
                continue
            kind = finding.get("kind")
            path_value = rec.get("path")
            if kind is None or path_value is None:
                continue
            kinds_by_path[path_value].add(kind)
            counts[kind] += 1
    return kinds_by_path, counts, parse_errors


def main():
    parser = argparse.ArgumentParser(
        description="Compare JSONL findings output and report per-kind deltas."
    )
    parser.add_argument("--base", required=True, help="Base JSONL findings file")
    parser.add_argument("--compare", required=True, help="Comparison JSONL findings file")
    parser.add_argument("--top", type=int, default=10, help="Top N changes to show")
    args = parser.parse_args()

    base_path = Path(args.base)
    compare_path = Path(args.compare)

    base_by_path, base_counts, base_errors = load_findings(base_path)
    cmp_by_path, cmp_counts, cmp_errors = load_findings(compare_path)

    all_paths = set(base_by_path.keys()) | set(cmp_by_path.keys())
    changed_paths = 0
    additions = Counter()
    removals = Counter()

    for path in all_paths:
        base_kinds = base_by_path.get(path, set())
        cmp_kinds = cmp_by_path.get(path, set())
        if base_kinds != cmp_kinds:
            changed_paths += 1
        for kind in cmp_kinds - base_kinds:
            additions[kind] += 1
        for kind in base_kinds - cmp_kinds:
            removals[kind] += 1

    print(f"Base findings file: {base_path}")
    print(f"Compare findings file: {compare_path}")
    print(f"Files in base: {len(base_by_path)}")
    print(f"Files in compare: {len(cmp_by_path)}")
    print(f"Files with changes: {changed_paths}")
    print(f"JSON parse errors (base): {base_errors}")
    print(f"JSON parse errors (compare): {cmp_errors}")
    print()

    print("Top additions:")
    for kind, count in additions.most_common(args.top):
        print(f"  {kind}: {count}")

    print()
    print("Top removals:")
    for kind, count in removals.most_common(args.top):
        print(f"  {kind}: {count}")

    print()
    print("Total unique kinds (base):", len(base_counts))
    print("Total unique kinds (compare):", len(cmp_counts))


if __name__ == "__main__":
    main()
