#!/usr/bin/env python3
"""
Test script to validate JavaScript extraction functionality
"""

import tempfile
import os
import subprocess
import json
from pathlib import Path

def create_test_js_content():
    """Create test JavaScript content that would trigger our enhanced sandbox features."""
    return '''
// Test JavaScript that exercises variable promotion and error recovery
eval("var M7pzjRpdcM5RVyTMS = 'test_value_from_eval';");

// This should work due to variable promotion
var result = M7pzjRpdcM5RVyTMS + "_processed";

// Test String.fromCharCode (common in malware)
var decoded = String.fromCharCode(72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100);

// Test unescape function
var unescaped = unescape("Hello%20World%21");

// Test console (should not throw errors)
console.log("Test execution");

// Test some undefined variables (should trigger error recovery)
try {
    var undefinedResult = someUndefinedVariable + " recovered";
} catch (e) {
    var undefinedResult = "fallback_value";
}

// Return final result
result + "_" + decoded + "_" + undefinedResult;
'''

def create_test_pdf_with_js(js_content):
    """Create a minimal PDF with JavaScript for testing."""
    # Very basic PDF structure with JavaScript
    pdf_content = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Action
/S /JavaScript
/JS ({js_content})
>>
endobj

4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj

xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000136 00000 n 
0000000200 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
267
%%EOF'''
    return pdf_content

def test_extraction():
    """Test the JavaScript extraction functionality."""
    print("🧪 Testing JavaScript extraction functionality...")
    
    # Create test content
    js_content = create_test_js_content()
    pdf_content = create_test_pdf_with_js(js_content.replace('\\n', '\\\\n').replace('"', '\\\\"'))
    
    # Create temporary test environment
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test PDF
        test_pdf = temp_path / "test_malware.pdf"
        with open(test_pdf, 'w') as f:
            f.write(pdf_content)
        
        # Create test directory structure
        pdf_dir = temp_path / "test_pdfs"
        pdf_dir.mkdir()
        
        # Copy test PDF to the directory
        import shutil
        shutil.copy2(test_pdf, pdf_dir / "test_malware.pdf")
        
        print(f"📁 Created test environment: {temp_dir}")
        print(f"📄 Test PDF: {pdf_dir}/test_malware.pdf")
        
        # Test basic sis-pdf extraction
        print("\\n🔧 Testing basic sis-pdf extraction...")
        try:
            temp_extract_dir = temp_path / "temp_extract"
            temp_extract_dir.mkdir()
            extract_cmd = f"cargo run -p sis-pdf -- extract --out {temp_extract_dir} js {test_pdf}"
            result = subprocess.run(extract_cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Check if files were extracted
                js_files = list(temp_extract_dir.glob("*.js"))
                if js_files:
                    print("✅ Basic extraction successful")
                    total_chars = sum(f.stat().st_size for f in js_files)
                    print(f"   Extracted {len(js_files)} file(s) with {total_chars} total characters")
                else:
                    print("⚠️  Extraction completed but no JS files found")
            else:
                print(f"⚠️  Basic extraction failed or returned no content")
                print(f"   stderr: {result.stderr}")
        except Exception as e:
            print(f"❌ Basic extraction error: {e}")
        
        # Test our extraction script
        print("\\n📤 Testing bulk extraction script...")
        try:
            extract_script_cmd = f"python3 /home/michiel/dev/sis-pdf/extract_js_payloads.py {pdf_dir} --output {temp_path}/test_results --create-test-suite"
            result = subprocess.run(extract_script_cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ Bulk extraction script successful")
                
                # Check results
                results_dir = temp_path / "test_results"
                if (results_dir / "extraction_summary.json").exists():
                    with open(results_dir / "extraction_summary.json") as f:
                        summary = json.load(f)
                    
                    print(f"   📊 Summary: {summary['extraction_summary']['total_payloads']} payloads extracted")
                    
                    # Check if payloads were created
                    payload_dir = results_dir / "payloads"
                    if payload_dir.exists():
                        payload_files = list(payload_dir.glob("*.js"))
                        print(f"   📄 Payload files created: {len(payload_files)}")
                        
                        if payload_files:
                            # Test enhanced sandbox on extracted payload
                            print("\\n🔬 Testing enhanced sandbox on extracted payload...")
                            test_payload = payload_files[0]
                            
                            sandbox_cmd = f"cargo run -p sis-pdf -- scan --json {test_payload}"
                            sandbox_result = subprocess.run(sandbox_cmd, shell=True, capture_output=True, text=True, timeout=30)
                            
                            if sandbox_result.returncode == 0:
                                try:
                                    scan_data = json.loads(sandbox_result.stdout)
                                    findings = scan_data.get('findings', [])
                                    js_findings = [f for f in findings if f.get('detector') == 'js_sandbox']
                                    
                                    print(f"✅ Enhanced sandbox analysis successful")
                                    print(f"   📋 Total findings: {len(findings)}")
                                    print(f"   🧪 JS sandbox findings: {len(js_findings)}")
                                    
                                    if js_findings:
                                        finding = js_findings[0]
                                        metadata = finding.get('metadata', {})
                                        print(f"   🔍 Calls detected: {metadata.get('js.runtime.calls', 'N/A')}")
                                        print(f"   ⚡ Execution time: {metadata.get('js.runtime.elapsed_ms', 'N/A')}ms")
                                        
                                except json.JSONDecodeError:
                                    print(f"⚠️  Could not parse sandbox results as JSON")
                            else:
                                print(f"❌ Enhanced sandbox test failed: {sandbox_result.stderr}")
                    
                else:
                    print("⚠️  No summary file created")
            else:
                print(f"❌ Bulk extraction failed: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Bulk extraction error: {e}")
        
        print(f"\\n🧹 Test environment will be cleaned up: {temp_dir}")

if __name__ == "__main__":
    test_extraction()