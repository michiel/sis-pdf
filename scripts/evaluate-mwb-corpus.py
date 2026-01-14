import os
import json
import datetime
import subprocess
import time
from pathlib import Path
from collections import defaultdict, Counter

# --- Configuration ---
CORPUS_ROOT = Path.home() / "corpus"
SIS_BINARY_PATH = "/usr/local/bin/sis"  # Assuming sis is in PATH or specify full path
OUTPUT_DIR = Path.home() / "analysis_results"
LOG_FILE = OUTPUT_DIR / "evaluation.log"

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def log_message(message: str):
    """Logs a message to the console and the log file."""
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()}: {message}\n")

def find_corpus_days(root_dir: Path) -> list[Path]:
    """Finds all mwb-YYYY-MM-DD directories."""
    log_message(f"Searching for corpus directories in {root_dir}...")
    day_dirs = []
    for item in root_dir.iterdir():
        if item.is_dir() and item.name.startswith("mwb-") and len(item.name) == 14:
            try:
                datetime.datetime.strptime(item.name[4:], "%Y-%m-%d")
                day_dirs.append(item)
            except ValueError:
                continue
    day_dirs.sort()
    log_message(f"Found {len(day_dirs)} corpus directories.")
    return day_dirs

def run_sis_scan(pdf_path: Path) -> dict:
    """Runs sis scan --deep on a PDF and returns parsed results."""
    log_message(f"Scanning {pdf_path}...")
    command = [
        "time", # Use time to measure execution duration
        str(SIS_BINARY_PATH),
        "scan",
        "--deep",
        str(pdf_path)
    ]
    
    # Run sis scan and capture output
    # Redirect stderr to stdout to capture warnings/errors from sis
    process = subprocess.run(command, capture_output=True, text=True, errors='ignore')
    
    scan_output = process.stdout
    scan_errors = process.stderr # This will contain the 'time' command's output
    
    # Extract real, user, sys time from stderr
    real_time_str = ""
    for line in scan_errors.splitlines():
        if line.startswith("real"):
            real_time_str = line.split("\t")[1]
            break
    
    # Convert time string (e.g., "0m1.234s") to seconds
    duration_seconds = 0.0
    if real_time_str:
        parts = real_time_str.replace('m', ' ').replace('s', '').split(' ')
        if len(parts) == 2:
            duration_seconds = float(parts[0]) * 60 + float(parts[1])
        elif len(parts) == 1:
            duration_seconds = float(parts[0])

    # Run sis query to get findings in JSON format
    query_command = [
        str(SIS_BINARY_PATH),
        "query",
        str(pdf_path),
        "findings",
        "--json"
    ]
    query_process = subprocess.run(query_command, capture_output=True, text=True, errors='ignore')
    
    findings_data = []
    if query_process.returncode == 0:
        # Filter out WARN messages from stdout before parsing JSON
        json_output_lines = [line for line in query_process.stdout.splitlines() if not line.startswith("2026-01-13T") and not line.startswith("WARN")]
        json_output = "\n".join(json_output_lines)
        try:
            # Find the actual JSON object in the output
            json_start = json_output.find('{')
            json_end = json_output.rfind('}')
            if json_start != -1 and json_end != -1:
                findings_json_str = json_output[json_start : json_end + 1]
                findings_result = json.loads(findings_json_str)
                findings_data = findings_result.get('result', [])
            else:
                log_message(f"Warning: Could not find JSON in sis query output for {pdf_path}")
        except json.JSONDecodeError as e:
            log_message(f"Error parsing JSON from sis query for {pdf_path}: {e}")
            log_message(f"Problematic JSON output: {json_output}")
    else:
        log_message(f"Error running sis query for {pdf_path}: {query_process.stderr}")

    return {
        "pdf_path": str(pdf_path),
        "duration_seconds": duration_seconds,
        "returncode": process.returncode,
        "stdout": scan_output,
        "stderr": scan_errors,
        "findings": findings_data,
        "error_count": scan_output.count("ERROR") + scan_errors.count("ERROR") ,
        "warning_count": scan_output.count("WARN") + scan_errors.count("WARN") ,
    }

def process_day_corpus(day_dir: Path, results_dir: Path):
    """Scans all PDFs in a day's corpus and saves results."""
    day_str = day_dir.name[4:] # YYYY-MM-DD
    day_results_path = results_dir / f"results-{day_str}.json"

    if day_results_path.exists():
        log_message(f"Results for {day_str} already exist. Skipping scan.")
        return json.loads(day_results_path.read_text())

    log_message(f"Processing corpus for {day_str}...")
    manifest_path = day_dir.parent / f"manifest-{day_dir.name}.json"
    
    if not manifest_path.exists():
        log_message(f"Warning: Manifest not found for {day_str}. Skipping.")
        return None

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    day_scan_results = []
    for sample in manifest:
        pdf_filename = sample["filename"]
        pdf_path = day_dir / pdf_filename
        if pdf_path.exists():
            scan_result = run_sis_scan(pdf_path)
            day_scan_results.append(scan_result)
        else:
            log_message(f"Warning: PDF file not found: {pdf_path}")
    
    with open(day_results_path, "w") as f:
        json.dump(day_scan_results, f, indent=4)
    
    log_message(f"Finished processing corpus for {day_str}.")
    return day_scan_results

def analyze_results(all_results: dict[str, list[dict]]):
    """Performs day-over-day and week-over-week analysis."""
    log_message("\n--- Analysis Report ---")
    
    dates = sorted(all_results.keys())
    if not dates:
        log_message("No data to analyze.")
        return

    # Day-over-day analysis
    log_message("\n--- Day-over-Day Analysis ---")
    for i in range(1, len(dates)):
        current_date = dates[i]
        previous_date = dates[i-1]
        
        current_day_results = all_results[current_date]
        previous_day_results = all_results[previous_date]
        
        log_message(f"\nComparison: {previous_date} vs {current_date}")
        compare_two_days(previous_day_results, current_day_results)

    # Week-over-week analysis (compare last day of current week with last day of previous week)
    log_message("\n--- Week-over-Week Analysis ---")
    if len(dates) >= 7:
        # Find the last day of each week
        weekly_comparison_dates = []
        current_week_end = None
        for d_str in dates:
            d = datetime.datetime.strptime(d_str, "%Y-%m-%d").date()
            if current_week_end is None:
                # Set current_week_end to the end of the week for the first date
                current_week_end = d + datetime.timedelta(days=6 - d.weekday())
            
            if d <= current_week_end:
                # If it's the end of the week or the last available day, add it
                if d == current_week_end or d == dates[-1]: 
                    weekly_comparison_dates.append(d_str)
            else:
                # Move to the next week
                current_week_end = d + datetime.timedelta(days=6 - d.weekday())
                weekly_comparison_dates.append(d_str)
        
        # Ensure we have at least two weeks to compare
        if len(weekly_comparison_dates) >= 2:
            for i in range(1, len(weekly_comparison_dates)):
                current_week_last_day = weekly_comparison_dates[i]
                previous_week_last_day = weekly_comparison_dates[i-1]
                
                log_message(f"\nComparison: Week ending {previous_week_last_day} vs Week ending {current_week_last_day}")
                compare_two_days(all_results[previous_week_last_day], all_results[current_week_last_day])
        else:
            log_message("Not enough data for week-over-week analysis (need at least two weeks).")
    else:
        log_message("Not enough data for week-over-week analysis (need at least 7 days).")

def compare_two_days(results1: list[dict], results2: list[dict]):
    """Compares scan results between two sets of data."""
    
    # Robustness
    errors1 = sum(r["error_count"] for r in results1)
    warnings1 = sum(r["warning_count"] for r in results1)
    scanned1 = len(results1)
    
    errors2 = sum(r["error_count"] for r in results2)
    warnings2 = sum(r["warning_count"] for r in results2)
    scanned2 = len(results2)

    log_message(f"  Robustness (Errors/Warnings): {errors1}/{warnings1} (Day1) vs {errors2}/{warnings2} (Day2)")
    
    # Speed
    total_time1 = sum(r["duration_seconds"] for r in results1)
    avg_time1 = total_time1 / scanned1 if scanned1 > 0 else 0
    
    total_time2 = sum(r["duration_seconds"] for r in results2)
    avg_time2 = total_time2 / scanned2 if scanned2 > 0 else 0

    log_message(f"  Speed (Avg/Total Scan Time): {avg_time1:.2f}s/{total_time1:.2f}s (Day1) vs {avg_time2:.2f}s/{total_time2:.2f}s (Day2)")

    # Top 25 Findings
    findings1 = Counter(f["kind"] for r in results1 for f in r["findings"])
    findings2 = Counter(f["kind"] for r in results2 for f in r["findings"])

    log_message("  Top 25 Findings (Day2 vs Day1):")
    top_findings2 = findings2.most_common(25)
    for kind, count2 in top_findings2:
        count1 = findings1.get(kind, 0)
        diff = count2 - count1
        log_message(f"    - {kind}: {count2} (Day2) vs {count1} (Day1) -> Diff: {diff}")

def main():
    log_message("Starting corpus evaluation script.")
    
    day_dirs = find_corpus_days(CORPUS_ROOT)
    
    all_results_by_date = {}
    for day_dir in day_dirs:
        day_str = day_dir.name[4:]
        results = process_day_corpus(day_dir, OUTPUT_DIR)
        if results:
            all_results_by_date[day_str] = results
            
    analyze_results(all_results_by_date)
    
    log_message("Corpus evaluation script finished.")

if __name__ == "__main__":
    main()
