from pathlib import Path


def parse_tracker(path: Path):
    lines = path.read_text().splitlines()
    table = []
    start = False
    for line in lines:
        if line.startswith("| Date |"):
            start = True
            continue
        if start:
            if line.startswith("|------"):
                continue
            if not line.strip() or not line.startswith("|"):
                break
            parts = [part.strip() for part in line.strip("|").split("|")]
            if len(parts) >= 8:
                table.append(parts[:8])
    return table


def main():
    tracker = Path("docs/threat-intel-tracker.md")
    if not tracker.exists():
        print("Tracker file missing")
        return
    rows = parse_tracker(tracker)
    if not rows:
        print("No tracker entries found")
        return
    print("Threat intelligence tracker summary:")
    for row in rows:
        date, cve, surface, detectors, severity, impact, confidence, notes = row
        print(f"- {date}: {cve} ({surface}) -> detectors={detectors}, severity={severity}, impact={impact}, confidence={confidence}; {notes}")


if __name__ == "__main__":
    main()
