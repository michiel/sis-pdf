#!/usr/bin/env python3
"""
JavaScript Analysis Gap Identifier

Analyzes test results from hostile JavaScript payloads to identify:
1. Missing sandbox APIs
2. Execution failures and patterns
3. Timeout causes
4. Opportunities for sandbox improvements
"""

import json
import subprocess
import sys
from pathlib import Path
from collections import Counter, defaultdict
import re

class GapAnalyzer:
    def __init__(self, payload_dir="extracted_js/payloads"):
        self.payload_dir = Path(payload_dir)
        self.results = []
        self.gaps = {
            'missing_apis': Counter(),
            'error_patterns': Counter(),
            'timeout_characteristics': [],
            'execution_failures': [],
            'unsupported_features': Counter()
        }

    def analyze_file(self, js_file: Path) -> dict:
        """Run analysis on a single JS file and collect gap data."""
        try:
            cmd = ["./target/release/sis-pdf", "scan", "--json", str(js_file)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)

            analysis = {
                'file': js_file.name,
                'output': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }

            # Try to parse JSON output
            try:
                data = json.loads(result.stdout)
                analysis['parsed'] = data

                # Extract gap information
                if 'dynamic_signals' in data:
                    ds = data['dynamic_signals']

                    # Check outcome
                    if ds.get('outcome') == 'timed_out':
                        self._analyze_timeout(js_file, data)
                    elif ds.get('outcome') == 'skipped':
                        reason = ds.get('reason', 'unknown')
                        self.gaps['unsupported_features'][f"skipped_{reason}"] += 1
                    elif ds.get('outcome') == 'executed':
                        # Check for execution errors
                        errors = ds.get('errors', [])
                        if errors:
                            self._analyze_errors(js_file, errors)

            except json.JSONDecodeError:
                # Check stderr for clues about failures
                if result.stderr:
                    self._analyze_stderr(js_file, result.stderr)

            return analysis

        except subprocess.TimeoutExpired:
            self.gaps['timeout_characteristics'].append({
                'file': js_file.name,
                'reason': 'process_timeout'
            })
            return {'file': js_file.name, 'error': 'timeout'}
        except Exception as e:
            return {'file': js_file.name, 'error': str(e)}

    def _analyze_timeout(self, js_file: Path, data: dict):
        """Analyze why a file timed out."""
        # Read the JS content to identify characteristics
        try:
            content = js_file.read_text(encoding='utf-8', errors='ignore')

            characteristics = {
                'file': js_file.name,
                'size': len(content),
                'has_while_loop': 'while' in content,
                'has_for_loop': 'for' in content,
                'has_eval': 'eval(' in content,
                'has_recursion': self._detect_recursion(content)
            }

            self.gaps['timeout_characteristics'].append(characteristics)
        except Exception as e:
            pass

    def _detect_recursion(self, content: str) -> bool:
        """Simple heuristic for detecting recursive patterns."""
        # Look for function calling itself
        func_pattern = r'function\s+(\w+)\s*\('
        functions = re.findall(func_pattern, content)

        for func in functions:
            # Check if function name appears in its own body
            if content.count(func) > 1:
                return True
        return False

    def _analyze_errors(self, js_file: Path, errors: list):
        """Analyze execution errors to identify missing features."""
        for error in errors:
            # Extract error type
            if isinstance(error, str):
                # Look for common patterns
                if 'is not defined' in error:
                    # Extract the undefined identifier
                    match = re.search(r"(\w+) is not defined", error)
                    if match:
                        self.gaps['missing_apis'][match.group(1)] += 1

                if 'is not a function' in error:
                    match = re.search(r"(\w+(?:\.\w+)*) is not a function", error)
                    if match:
                        self.gaps['missing_apis'][match.group(1)] += 1

                if 'has no property' in error or 'Cannot access property' in error:
                    match = re.search(r"property '?(\w+)'?", error)
                    if match:
                        self.gaps['missing_apis'][f"property_{match.group(1)}"] += 1

                # Categorize error pattern
                if 'ReferenceError' in error:
                    self.gaps['error_patterns']['ReferenceError'] += 1
                elif 'TypeError' in error:
                    self.gaps['error_patterns']['TypeError'] += 1
                elif 'SyntaxError' in error:
                    self.gaps['error_patterns']['SyntaxError'] += 1
                else:
                    self.gaps['error_patterns']['Other'] += 1

    def _analyze_stderr(self, js_file: Path, stderr: str):
        """Analyze stderr output for failure causes."""
        self.gaps['execution_failures'].append({
            'file': js_file.name,
            'stderr': stderr[:200]  # First 200 chars
        })

    def run_analysis(self, sample_size=None, file_pattern="*.js"):
        """Run gap analysis on payload files."""
        files = list(self.payload_dir.glob(file_pattern))

        if sample_size:
            import random
            files = random.sample(files, min(sample_size, len(files)))

        print(f"🔬 Analyzing {len(files)} files for capability gaps...")
        print()

        for i, js_file in enumerate(files, 1):
            print(f"\r[{i}/{len(files)}] {js_file.name[:60]:60}", end='', flush=True)
            result = self.analyze_file(js_file)
            self.results.append(result)

        print("\n")

    def generate_report(self):
        """Generate a comprehensive gap analysis report."""
        print("═" * 70)
        print("📊 JavaScript Sandbox Gap Analysis Report")
        print("═" * 70)
        print()

        # Missing APIs
        if self.gaps['missing_apis']:
            print("🔧 Missing or Incomplete APIs (Top 20):")
            print()
            for api, count in self.gaps['missing_apis'].most_common(20):
                print(f"   {api:40} : {count:4} occurrences")
            print()

        # Error patterns
        if self.gaps['error_patterns']:
            print("⚠️  Error Type Distribution:")
            print()
            total_errors = sum(self.gaps['error_patterns'].values())
            for error_type, count in self.gaps['error_patterns'].most_common():
                pct = (count / total_errors) * 100
                print(f"   {error_type:30} : {count:4} ({pct:5.1f}%)")
            print()

        # Timeout characteristics
        if self.gaps['timeout_characteristics']:
            print(f"⏱️  Timeout Analysis ({len(self.gaps['timeout_characteristics'])} files):")
            print()

            # Aggregate characteristics
            total = len(self.gaps['timeout_characteristics'])
            with_while = sum(1 for t in self.gaps['timeout_characteristics'] if t.get('has_while_loop'))
            with_for = sum(1 for t in self.gaps['timeout_characteristics'] if t.get('has_for_loop'))
            with_eval = sum(1 for t in self.gaps['timeout_characteristics'] if t.get('has_eval'))
            with_recursion = sum(1 for t in self.gaps['timeout_characteristics'] if t.get('has_recursion'))

            print(f"   Files with while loops    : {with_while:4} ({with_while*100/total:5.1f}%)")
            print(f"   Files with for loops      : {with_for:4} ({with_for*100/total:5.1f}%)")
            print(f"   Files with eval()         : {with_eval:4} ({with_eval*100/total:5.1f}%)")
            print(f"   Files with recursion      : {with_recursion:4} ({with_recursion*100/total:5.1f}%)")
            print()

        # Unsupported features
        if self.gaps['unsupported_features']:
            print("🚫 Unsupported Features:")
            print()
            for feature, count in self.gaps['unsupported_features'].most_common():
                print(f"   {feature:40} : {count:4} files")
            print()

        # Recommendations
        print("═" * 70)
        print("💡 Recommendations for Sandbox Improvements")
        print("═" * 70)
        print()

        recommendations = []

        # Based on missing APIs
        top_apis = [api for api, _ in self.gaps['missing_apis'].most_common(10)]
        if top_apis:
            recommendations.append(
                f"1. Implement missing APIs: {', '.join(top_apis[:5])}"
            )

        # Based on timeouts
        if self.gaps['timeout_characteristics']:
            recommendations.append(
                "2. Add loop detection/iteration limits to prevent infinite loops"
            )
            if sum(1 for t in self.gaps['timeout_characteristics'] if t.get('has_eval')) > 5:
                recommendations.append(
                    "3. Consider eval() execution depth limits"
                )

        # Based on error patterns
        if self.gaps['error_patterns'].get('ReferenceError', 0) > 10:
            recommendations.append(
                "4. Improve variable promotion and scope handling"
            )

        if self.gaps['error_patterns'].get('TypeError', 0) > 10:
            recommendations.append(
                "5. Add missing object methods and property stubs"
            )

        for i, rec in enumerate(recommendations, 1):
            print(f"   {rec}")

        print()

    def save_detailed_report(self, output_file="extracted_js/test_results/gap_analysis.json"):
        """Save detailed gap analysis to JSON."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = {
            'summary': {
                'files_analyzed': len(self.results),
                'total_missing_apis': len(self.gaps['missing_apis']),
                'total_timeouts': len(self.gaps['timeout_characteristics']),
                'total_errors': sum(self.gaps['error_patterns'].values())
            },
            'missing_apis': dict(self.gaps['missing_apis']),
            'error_patterns': dict(self.gaps['error_patterns']),
            'timeout_characteristics': self.gaps['timeout_characteristics'],
            'unsupported_features': dict(self.gaps['unsupported_features'])
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📝 Detailed report saved to: {output_path}")
        print()

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Analyze JS sandbox gaps and identify improvements')
    parser.add_argument('payload_dir', nargs='?', default='extracted_js/payloads',
                       help='Directory containing JS payloads')
    parser.add_argument('--sample', type=int, metavar='N',
                       help='Analyze only N random samples')
    parser.add_argument('--pattern', default='*.js',
                       help='File pattern to match (default: *.js)')
    parser.add_argument('--virusshare-only', action='store_true',
                       help='Analyze only VirusShare files')
    parser.add_argument('--output', default='extracted_js/test_results/gap_analysis.json',
                       help='Output file for detailed report')

    args = parser.parse_args()

    pattern = 'VirusShare_*.js' if args.virusshare_only else args.pattern

    analyzer = GapAnalyzer(args.payload_dir)
    analyzer.run_analysis(sample_size=args.sample, file_pattern=pattern)
    analyzer.generate_report()
    analyzer.save_detailed_report(args.output)

if __name__ == '__main__':
    main()
