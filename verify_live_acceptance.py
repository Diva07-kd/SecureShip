"""
Empirical Acceptance Criteria Verification Script for Milestone 3.
Executes live container validation for AC-4, AC-5, and AC-6 against SecureShip-IDE.
"""

import io
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND_BASE = "http://localhost:8000"
FRONTEND_PROXY_BASE = "http://localhost:3000"
FIXTURES_DIR = Path(r"C:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\tests\fixtures")

def upload_zip(base_url: str, file_path: Path, filename: str = None) -> tuple[int, dict]:
    boundary = f"----BoundaryScan{int(time.time()*1000)}"
    fname = filename or file_path.name
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{base_url}/api/scan",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(err_body)
        except Exception:
            return e.code, {"raw": err_body}

def poll_job(base_url: str, job_id: str, max_wait: int = 180) -> dict:
    start_time = time.time()
    while time.time() - start_time < max_wait:
        req = urllib.request.Request(f"{base_url}/api/jobs/{job_id}")
        with urllib.request.urlopen(req) as resp:
            job_data = json.loads(resp.read().decode("utf-8"))
        status = job_data.get("status")
        stage = job_data.get("stage")
        progress = job_data.get("progress")
        print(f"  [Poll {int(time.time() - start_time)}s] status={status}, stage={stage}, progress={progress}%")
        if status in ("done", "failed"):
            return job_data
        time.sleep(3)
    raise TimeoutError(f"Job {job_id} did not finish within {max_wait}s")

def get_report(base_url: str, job_id: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"{base_url}/api/reports/{job_id}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(err_body)
        except Exception:
            return e.code, {"raw": err_body}

def get_export(base_url: str, job_id: str, fmt: str) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(f"{base_url}/api/reports/{job_id}/export?format={fmt}")
    try:
        with urllib.request.urlopen(req) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            content = resp.read()
            return resp.status, headers, content
    except urllib.error.HTTPError as e:
        err_body = e.read()
        return e.code, {k.lower(): v for k, v in e.headers.items()}, err_body


def test_ac4_valid_vulnerable_scan():
    print("\n=======================================================")
    print("Executing AC-4: Live Scan valid_vulnerable.zip")
    print("=======================================================")

    # 1. Test direct upload to backend
    vuln_path = FIXTURES_DIR / "valid_vulnerable.zip"
    assert vuln_path.exists(), f"Fixture {vuln_path} missing!"

    print(f"Uploading {vuln_path} to {BACKEND_BASE}/api/scan ...")
    status, upload_resp = upload_zip(BACKEND_BASE, vuln_path)
    assert status == 200, f"Upload failed: status={status}, resp={upload_resp}"
    job_id = upload_resp["job_id"]
    print(f"Uploaded successfully. Job ID: {job_id}")

    # 2. Poll until completed (test polling via proxy too)
    print("Polling job status via backend ...")
    job = poll_job(BACKEND_BASE, job_id, max_wait=200)
    assert job["status"] == "done", f"Job failed: {job}"
    print(f"Job completed successfully in stage '{job.get('stage')}'")

    # Verify polling via frontend proxy also works
    proxy_job_req = urllib.request.Request(f"{FRONTEND_PROXY_BASE}/api/jobs/{job_id}")
    with urllib.request.urlopen(proxy_job_req) as resp:
        proxy_job = json.loads(resp.read().decode("utf-8"))
        assert proxy_job["status"] == "done", "Proxy job retrieval mismatch"
    print("Verified job status retrieval via Frontend Nginx Proxy (port 3000)!")

    # 3. Retrieve report and verify findings
    report_status, report = get_report(BACKEND_BASE, job_id)
    assert report_status == 200, f"Report failed with status {report_status}: {report}"

    findings = report.get("findings", [])
    print(f"Total findings detected: {len(findings)}")
    rule_ids = {f.get("rule_id") for f in findings}
    print("Detected Rule IDs:", rule_ids)

    # Assert all 4 expected findings
    expected = {
        "secureship-py-pickle-load": "pickle deserialization",
        "secureship-js-eval": "eval code injection",
        "CKV_DOCKER_2": "missing HEALTHCHECK",
        "CKV_DOCKER_8": "root USER",
    }
    for rule_id, desc in expected.items():
        assert rule_id in rule_ids, f"FAIL: Expected finding '{rule_id}' ({desc}) not found in scan results!"
        # Print details of the finding
        matching = [f for f in findings if f.get("rule_id") == rule_id][0]
        print(f"  [+] Found '{rule_id}' ({desc}): severity={matching.get('severity')}, file={matching.get('file_path')}:{matching.get('start_line')}")

    assert len(findings) == 4, f"Expected exactly 4 findings, but got {len(findings)}"
    print("AC-4 VERIFIED: All 4 expected findings detected without timeout!")
    return job_id


def test_ac5_benign_and_edge_cases():
    print("\n=======================================================")
    print("Executing AC-5: Live Scan Benign & Edge-Case Archives")
    print("=======================================================")

    # 1. Clean Archive: valid_clean.zip (upload via Frontend Proxy port 3000 to test proxy upload!)
    clean_path = FIXTURES_DIR / "valid_clean.zip"
    print(f"\n1. Uploading {clean_path.name} via Nginx Proxy {FRONTEND_PROXY_BASE}/api/scan ...")
    clean_status, clean_upload = upload_zip(FRONTEND_PROXY_BASE, clean_path)
    assert clean_status == 200, f"Clean upload failed: {clean_status}, {clean_upload}"
    clean_job_id = clean_upload["job_id"]
    print(f"Clean job uploaded via proxy. Job ID: {clean_job_id}")

    clean_job = poll_job(FRONTEND_PROXY_BASE, clean_job_id, max_wait=120)
    assert clean_job["status"] == "done", f"Clean job status was not 'done': {clean_job}"

    rep_status, clean_report = get_report(FRONTEND_PROXY_BASE, clean_job_id)
    assert rep_status == 200
    clean_findings = clean_report.get("findings", [])
    print(f"Clean findings count: {len(clean_findings)}")
    assert len(clean_findings) == 0, f"Expected 0 findings for clean archive, got {len(clean_findings)}"
    print("PASS: valid_clean.zip scanned with exactly 0 findings!")

    # 2. Corrupt Archive: corrupt.zip
    corrupt_path = FIXTURES_DIR / "corrupt.zip"
    print(f"\n2. Uploading {corrupt_path.name} to {BACKEND_BASE}/api/scan ...")
    corrupt_status, corrupt_upload = upload_zip(BACKEND_BASE, corrupt_path)
    assert corrupt_status == 200, f"Corrupt initial upload failed: {corrupt_status}, {corrupt_upload}"
    corrupt_job_id = corrupt_upload["job_id"]
    print(f"Corrupt job queued. Job ID: {corrupt_job_id}")

    corrupt_job = poll_job(BACKEND_BASE, corrupt_job_id, max_wait=60)
    assert corrupt_job["status"] == "failed", f"Expected status 'failed', got {corrupt_job['status']}"
    print(f"Corrupt job failed gracefully with error: {corrupt_job.get('error')}")

    # Fetch report for failed job -> must return 422
    rep_status, rep_err = get_report(BACKEND_BASE, corrupt_job_id)
    assert rep_status == 422, f"Expected 422 for failed job report, got {rep_status}"
    print(f"PASS: Fetching report for corrupt job returned HTTP {rep_status} (Unprocessable Entity)")

    # 3. Non-Zip File: test.txt
    print("\n3. Testing non-zip file upload rejection (HTTP 400) ...")
    boundary = f"----BoundaryScan{int(time.time()*1000)}"
    text_content = b"This is plain text, not a zip."
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test_file.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode("utf-8") + text_content + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{BACKEND_BASE}/api/scan",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            assert False, f"Expected 400 for text file, but got status {resp.status}"
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"Expected 400, got {e.code}"
        print(f"PASS: Non-zip file rejected with HTTP {e.code}: {e.read().decode('utf-8')}")

    # 4. Oversized upload rejection with HTTP 413
    print("\n4. Testing oversized archive rejection (>600MB/650MB) with HTTP 413 ...")
    try:
        oversized_req = urllib.request.Request(
            f"{FRONTEND_PROXY_BASE}/api/scan",
            data=b"X",
            headers={
                "Content-Type": "multipart/form-data; boundary=----BoundaryOversized",
                "Content-Length": "700000000",
            },
        )
        with urllib.request.urlopen(oversized_req) as resp:
            assert False, f"Expected 413 for oversized file, but got status {resp.status}"
    except urllib.error.HTTPError as e:
        assert e.code == 413, f"Expected 413, got {e.code}"
        print(f"PASS: Oversized upload (>650MB) rejected with HTTP {e.code} ({e.reason}) via Nginx proxy!")

    print("AC-5 VERIFIED: Benign, corrupt, non-zip, and oversized edge cases handled properly!")


def test_ac6_export_all_formats(job_id: str):
    print("\n=======================================================")
    print("Executing AC-6: Export Scan Results Across All 4 Formats")
    print("=======================================================")

    formats = [
        ("json", "application/json", None),
        ("sarif", "application/sarif+json", None),
        ("html", "text/html; charset=utf-8", b"<!DOCTYPE html>"),
        ("pdf", "application/pdf", b"%PDF-"),
    ]

    for fmt, expected_mime, magic_bytes in formats:
        print(f"\nTesting export format '{fmt}' on job {job_id} ...")
        # Test direct backend export
        status, headers, content = get_export(BACKEND_BASE, job_id, fmt)
        assert status == 200, f"Export {fmt} failed with status {status}"
        
        content_type = headers.get("content-type", "")
        content_disposition = headers.get("content-disposition", "")
        assert expected_mime in content_type, f"MIME mismatch for {fmt}: expected {expected_mime}, got {content_type}"
        assert f"securescan-report-{job_id}.{fmt}" in content_disposition, f"Filename mismatch in Content-Disposition: {content_disposition}"

        if magic_bytes:
            assert content.startswith(magic_bytes), f"Content for {fmt} did not start with {magic_bytes}"

        if fmt == "json":
            json_data = json.loads(content.decode("utf-8"))
            assert "schemaVersion" in json_data
            assert "findings" in json_data
            assert len(json_data["findings"]) == 4
            print(f"  [+] JSON payload valid: {len(content)} bytes, {len(json_data['findings'])} findings")
        elif fmt == "sarif":
            sarif_data = json.loads(content.decode("utf-8"))
            assert sarif_data.get("version") == "2.1.0"
            assert "runs" in sarif_data
            assert len(sarif_data["runs"]) > 0
            results = sarif_data["runs"][0].get("results", [])
            assert len(results) == 4
            print(f"  [+] SARIF 2.1.0 payload valid: {len(content)} bytes, {len(results)} results")
        elif fmt == "html":
            html_text = content.decode("utf-8")
            assert "SecureScan" in html_text
            assert "pickle" in html_text.lower()
            assert "eval" in html_text.lower()
            print(f"  [+] HTML report valid: {len(content)} bytes, standalone HTML with findings")
        elif fmt == "pdf":
            assert len(content) > 1000
            print(f"  [+] PDF binary valid: {len(content)} bytes, starts with %PDF-")

        # Test proxy export as well
        proxy_status, proxy_headers, proxy_content = get_export(FRONTEND_PROXY_BASE, job_id, fmt)
        assert proxy_status == 200, f"Proxy export {fmt} failed: {proxy_status}"
        if magic_bytes:
            assert proxy_content.startswith(magic_bytes), f"Proxy {fmt} missing magic bytes"
        assert len(proxy_content) > 0, f"Proxy {fmt} content empty"
        print(f"  [+] Verified export '{fmt}' via Nginx Proxy (port 3000): {len(proxy_content)} bytes")

    print("\nAC-6 VERIFIED: All 4 export formats generated and validated with status 200!")


if __name__ == "__main__":
    import sys
    print("STARTING LIVE ACCEPTANCE VERIFICATION...")
    t0 = time.time()
    
    # AC-4: Scan valid_vulnerable.zip (or use existing job if specified)
    if len(sys.argv) > 1 and sys.argv[1].strip():
        vuln_job_id = sys.argv[1].strip()
        print(f"Using specified completed job ID: {vuln_job_id}")
        # Verify findings on this job
        report_status, report = get_report(BACKEND_BASE, vuln_job_id)
        assert report_status == 200, f"Report failed: {report}"
        findings = report.get("findings", [])
        print(f"Total findings detected: {len(findings)}")
        rule_ids = {f.get("rule_id") for f in findings}
        print("Detected Rule IDs:", rule_ids)
        expected = {
            "secureship-py-pickle-load": "pickle deserialization",
            "secureship-js-eval": "eval code injection",
            "CKV_DOCKER_2": "missing HEALTHCHECK",
            "CKV_DOCKER_8": "root USER",
        }
        for rule_id, desc in expected.items():
            assert rule_id in rule_ids, f"FAIL: Expected finding '{rule_id}' ({desc}) not found!"
            print(f"  [+] Found '{rule_id}' ({desc})")
        assert len(findings) == 4
        print("AC-4 VERIFIED: All 4 expected findings confirmed!")
    else:
        vuln_job_id = test_ac4_valid_vulnerable_scan()

    # AC-5: Benign and edge case archives
    test_ac5_benign_and_edge_cases()

    # AC-6: Export completed scan in JSON, SARIF, HTML, PDF
    test_ac6_export_all_formats(vuln_job_id)

    total_time = round(time.time() - t0, 2)
    print("\n=======================================================")
    print(f"ALL ACCEPTANCE CRITERIA EMPIRICALLY VERIFIED IN {total_time}s!")
    print("=======================================================")
