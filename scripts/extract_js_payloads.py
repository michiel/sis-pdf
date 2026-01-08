#!/usr/bin/env python3
"""
JavaScript Payload Extractor for Bulk Testing

This script extracts JavaScript payloads from a directory of PDF files using sis-pdf
and prepares them for bulk static and dynamic analysis testing.
"""

import argparse
import json
import os
import subprocess
import sys
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import shutil

class JavaScriptExtractor:
    def __init__(self, sis_binary: str = "cargo run -p sis-pdf --", 
                 output_dir: str = "extracted_js", max_workers: int = 4):
        self.sis_binary = sis_binary
        self.output_dir = Path(output_dir)
        self.max_workers = max_workers
        self.results = []
        
        # Create output directories
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "payloads").mkdir(exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)
        (self.output_dir / "test_results").mkdir(exist_ok=True)
        
    def extract_js_from_pdf(self, pdf_path: Path) -> Dict:
        """Extract JavaScript payloads from a single PDF file."""
        result = {
            'pdf_path': str(pdf_path),
            'pdf_name': pdf_path.name,
            'file_size': pdf_path.stat().st_size,
            'timestamp': time.time(),
            'payloads': [],
            'scan_results': None,
            'errors': []
        }
        
        try:
            # First, run a full scan to get overall analysis
            print(f"Scanning {pdf_path.name}...")
            scan_cmd = f"{self.sis_binary} scan --json {pdf_path}"
            scan_process = subprocess.run(
                scan_cmd, shell=True, capture_output=True, text=True, timeout=120
            )
            
            if scan_process.returncode == 0:
                try:
                    result['scan_results'] = json.loads(scan_process.stdout)
                except json.JSONDecodeError:
                    result['errors'].append("Failed to parse scan JSON output")
            else:
                result['errors'].append(f"Scan failed: {scan_process.stderr}")
            
            # Extract JavaScript payloads using correct sis extract command
            temp_out_dir = tempfile.mkdtemp()
            try:
                extract_cmd = f"{self.sis_binary} extract --out {temp_out_dir} js {pdf_path}"
                extract_process = subprocess.run(
                    extract_cmd, shell=True, capture_output=True, text=True, timeout=60
                )
                
                if extract_process.returncode == 0:
                    # Check for extracted JavaScript files in temp directory
                    temp_path = Path(temp_out_dir)
                    js_files = list(temp_path.glob("*.js"))
                    
                    if js_files:
                        for i, js_file in enumerate(js_files):
                            try:
                                with open(js_file, 'r', encoding='utf-8') as f:
                                    js_content = f.read()
                                
                                # Create payload info from extracted file
                                payload_info = self._save_raw_payload(pdf_path, js_content, i)
                                result['payloads'].append(payload_info)
                                
                            except Exception as e:
                                result['errors'].append(f"Failed to read extracted JS file {js_file}: {str(e)}")
                    else:
                        # Check if extraction produced other output
                        all_files = list(temp_path.glob("*"))
                        if all_files:
                            result['errors'].append(f"Extraction produced files but no .js: {[f.name for f in all_files]}")
                        else:
                            result['errors'].append("No JavaScript extracted - PDF may not contain JS")
                else:
                    result['errors'].append(f"Extract failed: {extract_process.stderr}")
                    
            finally:
                # Clean up temp directory
                shutil.rmtree(temp_out_dir, ignore_errors=True)
                
        except subprocess.TimeoutExpired:
            result['errors'].append("Process timed out")
        except Exception as e:
            result['errors'].append(f"Unexpected error: {str(e)}")
            
        return result
    
    def _save_payload(self, pdf_path: Path, js_entry: Dict, index: int) -> Dict:
        """Save a JavaScript payload and return metadata."""
        # Generate unique filename
        pdf_hash = hashlib.md5(str(pdf_path).encode()).hexdigest()[:8]
        js_content = js_entry.get('content', js_entry.get('code', ''))
        js_hash = hashlib.md5(js_content.encode()).hexdigest()[:8]
        
        payload_filename = f"{pdf_path.stem}_{pdf_hash}_{index}_{js_hash}.js"
        payload_path = self.output_dir / "payloads" / payload_filename
        
        # Save payload
        with open(payload_path, 'w', encoding='utf-8') as f:
            f.write(js_content)
        
        return {
            'index': index,
            'filename': payload_filename,
            'path': str(payload_path),
            'size': len(js_content),
            'hash': js_hash,
            'metadata': js_entry
        }
    
    def _save_raw_payload(self, pdf_path: Path, js_content: str, index: int) -> Dict:
        """Save raw JavaScript content when JSON parsing fails."""
        pdf_hash = hashlib.md5(str(pdf_path).encode()).hexdigest()[:8]
        js_hash = hashlib.md5(js_content.encode()).hexdigest()[:8]
        
        payload_filename = f"{pdf_path.stem}_{pdf_hash}_{index}_{js_hash}.js"
        payload_path = self.output_dir / "payloads" / payload_filename
        
        with open(payload_path, 'w', encoding='utf-8') as f:
            f.write(js_content)
        
        return {
            'index': index,
            'filename': payload_filename,
            'path': str(payload_path),
            'size': len(js_content),
            'hash': js_hash,
            'metadata': {'raw_extraction': True}
        }
    
    def process_pdf_directory(self, pdf_dir: Path, pattern: str = "*.pdf") -> None:
        """Process all PDF files in a directory."""
        pdf_files = list(pdf_dir.glob(pattern))
        
        if not pdf_files:
            print(f"No PDF files found in {pdf_dir} matching pattern {pattern}")
            return
        
        print(f"Found {len(pdf_files)} PDF files to process...")
        
        # Process files concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_pdf = {
                executor.submit(self.extract_js_from_pdf, pdf_path): pdf_path 
                for pdf_path in pdf_files
            }
            
            for future in as_completed(future_to_pdf):
                pdf_path = future_to_pdf[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    payload_count = len(result['payloads'])
                    if payload_count > 0:
                        print(f"✅ {pdf_path.name}: {payload_count} payload(s) extracted")
                    else:
                        print(f"⚠️  {pdf_path.name}: No JavaScript found")
                        if result['errors']:
                            print(f"   Errors: {'; '.join(result['errors'])}")
                            
                except Exception as e:
                    print(f"❌ {pdf_path.name}: Failed - {str(e)}")
    
    def generate_summary_report(self) -> None:
        """Generate a comprehensive summary report."""
        summary = {
            'extraction_summary': {
                'total_pdfs': len(self.results),
                'pdfs_with_js': len([r for r in self.results if r['payloads']]),
                'total_payloads': sum(len(r['payloads']) for r in self.results),
                'total_errors': sum(len(r['errors']) for r in self.results)
            },
            'payload_stats': {},
            'error_analysis': {},
            'extraction_results': self.results
        }
        
        # Payload statistics
        all_payloads = []
        for result in self.results:
            all_payloads.extend(result['payloads'])
        
        if all_payloads:
            sizes = [p['size'] for p in all_payloads]
            summary['payload_stats'] = {
                'count': len(all_payloads),
                'size_min': min(sizes),
                'size_max': max(sizes),
                'size_avg': sum(sizes) / len(sizes),
                'unique_hashes': len(set(p['hash'] for p in all_payloads))
            }
        
        # Error analysis
        all_errors = []
        for result in self.results:
            all_errors.extend(result['errors'])
        
        error_counts = {}
        for error in all_errors:
            error_type = error.split(':')[0] if ':' in error else error
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        summary['error_analysis'] = error_counts
        
        # Save summary
        summary_path = self.output_dir / "extraction_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n📊 Extraction Summary:")
        print(f"   PDFs processed: {summary['extraction_summary']['total_pdfs']}")
        print(f"   PDFs with JS: {summary['extraction_summary']['pdfs_with_js']}")
        print(f"   Total payloads: {summary['extraction_summary']['total_payloads']}")
        print(f"   Unique payloads: {summary['payload_stats'].get('unique_hashes', 0)}")
        print(f"   Summary saved to: {summary_path}")

def create_test_suite(output_dir: Path) -> None:
    """Create a comprehensive test suite for the extracted payloads."""
    test_script = output_dir / "run_bulk_tests.py"
    
    test_content = '''#!/usr/bin/env python3
"""
Bulk JavaScript Analysis Test Suite

Runs both static and dynamic analysis on all extracted JavaScript payloads.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

class BulkJSAnalyzer:
    def __init__(self, payload_dir: str, sis_binary: str = "cargo run -p sis-pdf --"):
        self.payload_dir = Path(payload_dir)
        self.sis_binary = sis_binary
        self.results = []
        
    def analyze_payload(self, js_file: Path) -> dict:
        """Analyze a single JavaScript payload with both static and dynamic analysis."""
        result = {
            'filename': js_file.name,
            'path': str(js_file),
            'size': js_file.stat().st_size,
            'timestamp': time.time(),
            'static_analysis': {},
            'dynamic_analysis': {},
            'errors': []
        }
        
        try:
            # Read JavaScript content
            with open(js_file, 'r', encoding='utf-8') as f:
                js_content = f.read()
            
            # Create a temporary PDF with this JavaScript for analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as tmp_js:
                tmp_js.write(js_content)
                tmp_js_path = tmp_js.name
            
            try:
                # Run dynamic analysis via sis scan (this will use our enhanced sandbox)
                scan_cmd = f"{self.sis_binary} scan --json --no-js-ast {tmp_js_path}"
                scan_process = subprocess.run(
                    scan_cmd, shell=True, capture_output=True, text=True, timeout=30
                )
                
                if scan_process.returncode == 0:
                    try:
                        scan_results = json.loads(scan_process.stdout)
                        result['dynamic_analysis'] = scan_results
                    except json.JSONDecodeError:
                        result['errors'].append("Failed to parse dynamic analysis results")
                else:
                    result['errors'].append(f"Dynamic analysis failed: {scan_process.stderr}")
                
            finally:
                os.unlink(tmp_js_path)
                
        except Exception as e:
            result['errors'].append(f"Analysis failed: {str(e)}")
            
        return result
    
    def run_bulk_analysis(self, max_workers: int = 4) -> None:
        """Run analysis on all payloads in the directory."""
        js_files = list(self.payload_dir.glob("*.js"))
        
        if not js_files:
            print(f"No JavaScript files found in {self.payload_dir}")
            return
        
        print(f"Analyzing {len(js_files)} JavaScript payloads...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.analyze_payload, js_file): js_file 
                for js_file in js_files
            }
            
            for future in as_completed(future_to_file):
                js_file = future_to_file[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    if result['errors']:
                        print(f"⚠️  {js_file.name}: {len(result['errors'])} errors")
                    else:
                        print(f"✅ {js_file.name}: Analysis completed")
                        
                except Exception as e:
                    print(f"❌ {js_file.name}: Failed - {str(e)}")
        
        # Save results
        results_path = Path("test_results") / "bulk_analysis_results.json"
        results_path.parent.mkdir(exist_ok=True)
        
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\\n📊 Analysis complete. Results saved to: {results_path}")
        
        # Generate summary
        self.generate_analysis_summary()
    
    def generate_analysis_summary(self) -> None:
        """Generate analysis summary statistics."""
        total = len(self.results)
        successful = len([r for r in self.results if not r['errors']])
        
        print(f"\\n📈 Analysis Summary:")
        print(f"   Total payloads: {total}")
        print(f"   Successful analyses: {successful}")
        print(f"   Failed analyses: {total - successful}")
        
        if successful > 0:
            # Count findings
            total_findings = 0
            js_sandbox_findings = 0
            
            for result in self.results:
                if 'dynamic_analysis' in result and 'findings' in result['dynamic_analysis']:
                    findings = result['dynamic_analysis']['findings']
                    total_findings += len(findings)
                    js_sandbox_findings += len([f for f in findings if f.get('detector') == 'js_sandbox'])
            
            print(f"   Total findings: {total_findings}")
            print(f"   JS sandbox findings: {js_sandbox_findings}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Bulk JavaScript Analysis Test Suite")
    parser.add_argument("payload_dir", help="Directory containing extracted JS payloads")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker threads")
    parser.add_argument("--sis-binary", default="cargo run -p sis-pdf --",
                       help="Command to run sis-pdf")
    
    args = parser.parse_args()
    
    analyzer = BulkJSAnalyzer(args.payload_dir, args.sis_binary)
    analyzer.run_bulk_analysis(args.workers)
'''
    
    with open(test_script, 'w') as f:
        f.write(test_content)
    
    test_script.chmod(0o755)
    print(f"📋 Test suite created: {test_script}")

def main():
    parser = argparse.ArgumentParser(description="Extract JavaScript payloads from PDF files for bulk testing")
    parser.add_argument("pdf_directory", help="Directory containing PDF files")
    parser.add_argument("--output", "-o", default="extracted_js", help="Output directory")
    parser.add_argument("--pattern", default="*.pdf", help="File pattern to match")
    parser.add_argument("--workers", "-w", type=int, default=4, help="Number of worker threads")
    parser.add_argument("--sis-binary", default="cargo run -p sis-pdf --",
                       help="Command to run sis-pdf")
    parser.add_argument("--create-test-suite", action="store_true",
                       help="Create bulk test suite scripts")
    
    args = parser.parse_args()
    
    pdf_dir = Path(args.pdf_directory)
    if not pdf_dir.exists():
        print(f"❌ Directory not found: {pdf_dir}")
        sys.exit(1)
    
    # Initialize extractor
    extractor = JavaScriptExtractor(
        sis_binary=args.sis_binary,
        output_dir=args.output,
        max_workers=args.workers
    )
    
    print(f"🔍 Extracting JavaScript from PDFs in: {pdf_dir}")
    print(f"📁 Output directory: {extractor.output_dir}")
    print(f"⚡ Using {args.workers} worker threads")
    
    # Process PDFs
    start_time = time.time()
    extractor.process_pdf_directory(pdf_dir, args.pattern)
    end_time = time.time()
    
    # Generate summary
    extractor.generate_summary_report()
    
    print(f"⏱️  Total time: {end_time - start_time:.2f} seconds")
    
    # Create test suite if requested
    if args.create_test_suite:
        create_test_suite(extractor.output_dir)
        print(f"\\n🚀 To run bulk analysis:")
        print(f"   cd {extractor.output_dir}")
        print(f"   python3 run_bulk_tests.py payloads/")

if __name__ == "__main__":
    main()