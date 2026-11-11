"""
Empirical Challenge Verification Suite for Milestone 3 Gate (AC-5 and AC-6)
Executed by: challenger_m3_2 (Export & Edge Case Challenger)
Target: SecureShip-IDE live running containers (ports 8000 and 3000)
"""

import io
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND_BASE = "http://localhost:8000"
FRONTEND_PROXY_BASE = "http://localhost:3000"
FIXTURES_DIR = Path(r"C:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\tests\fixtures")

test_results = []

def record(test_name: str, passed: bool, details: str = ""):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {test_name}: {details}")
    test_results.append({"test": test_name, "passed": passed, "details": details})
    if not passed:
        print(f"FAILED ASSERTION in {test_name}: {details}", file=sys.stderr)


def upload_zip(base_url: str, file_path: Path, filename: str = None, mime: str = "application/zip") -> tuple[int, dict]:
    boundary = f"----BoundaryScan{int(time.time()*1000)}"
    fname = filename or file_path.name
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
        f"Content-Type: {mime}\r\n\r\n"
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
        if status in ("done", "failed"):
            return job_data
        time.sleep(2)
    raise TimeoutError(f"Job {job_id} did not complete within {max_wait}s")


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


# ==============================================================================
# SECTION 1: ACCEPTANCE CRITERION 5 CHALLENGES
# ==============================================================================
def challenge_ac5_benign_and_edge_cases():
    print("\n" + "="*70)
    print("CHALLENGE AC-5: Live Scan Benign & Edge-Case Archives")
    print("="*70)

    # 1. Benign clean archive: valid_clean.zip (upload via proxy port 3000)
    clean_path = FIXTURES_DIR / "valid_clean.zip"
    assert clean_path.exists(), f"Missing fixture: {clean_path}"
    
    print("\n[Test AC5.1] Scanning valid_clean.zip via Nginx proxy (port 3000)...")
    c_status, c_upload = upload_zip(FRONTEND_PROXY_BASE, clean_path)
    clean_job_id = c_upload.get("job_id")
    record("AC5.1 Upload valid_clean.zip via proxy", c_status == 200 and bool(clean_job_id), f"Status: {c_status}, Job ID: {clean_job_id}")
    
    clean_job = poll_job(FRONTEND_PROXY_BASE, clean_job_id, max_wait=90)
    record("AC5.1 Scan status is 'done'", clean_job.get("status") == "done", f"Final status: {clean_job.get('status')}")
    record("AC5.1 Scan progress is 100%", clean_job.get("progress") == 100, f"Progress: {clean_job.get('progress')}%")

    # Verify report retrieval on clean job via direct backend and proxy
    r_status, clean_report = get_report(BACKEND_BASE, clean_job_id)
    findings = clean_report.get("findings", [])
    record("AC5.1 Backend report returns 200 OK", r_status == 200, f"Status: {r_status}")
    record("AC5.1 Exactly 0 findings in valid_clean.zip", len(findings) == 0, f"Findings count: {len(findings)}")

    pr_status, proxy_clean_report = get_report(FRONTEND_PROXY_BASE, clean_job_id)
    record("AC5.1 Proxy report returns 200 OK with 0 findings", pr_status == 200 and len(proxy_clean_report.get("findings", [])) == 0, f"Proxy status: {pr_status}")

    # 2. Corrupt archive: corrupt.zip
    corrupt_path = FIXTURES_DIR / "corrupt.zip"
    assert corrupt_path.exists(), f"Missing fixture: {corrupt_path}"
    print("\n[Test AC5.2] Scanning corrupt.zip via backend (port 8000)...")
    cor_status, cor_upload = upload_zip(BACKEND_BASE, corrupt_path)
    cor_job_id = cor_upload.get("job_id")
    record("AC5.2 Upload corrupt.zip accepted to queue", cor_status == 200 and bool(cor_job_id), f"Job ID: {cor_job_id}")

    cor_job = poll_job(BACKEND_BASE, cor_job_id, max_wait=60)
    record("AC5.2 Job status transitions to 'failed'", cor_job.get("status") == "failed", f"Status: {cor_job.get('status')}")
    record("AC5.2 Error detail indicates archive corruption", "zip" in str(cor_job.get("error", "")).lower() or "corrupt" in str(cor_job.get("error", "")).lower(), f"Error: {cor_job.get('error')}")

    # Fetch report for corrupt job -> must return 422
    cr_status, cr_resp = get_report(BACKEND_BASE, cor_job_id)
    record("AC5.2 Fetching report for corrupt job returns HTTP 422", cr_status == 422, f"HTTP status: {cr_status}, Detail: {cr_resp.get('detail')}")

    # Same corrupt report retrieval via proxy port 3000
    p_cr_status, p_cr_resp = get_report(FRONTEND_PROXY_BASE, cor_job_id)
    record("AC5.2 Proxy returns HTTP 422 for corrupt job report", p_cr_status == 422, f"HTTP status: {p_cr_status}")

    # 3. Non-zip upload rejection (HTTP 400)
    print("\n[Test AC5.3] Non-zip text file upload rejection (HTTP 400)...")
    boundary = f"----BoundaryNonZip{int(time.time()*1000)}"
    body_txt = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="malicious_script.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"print('not a zip file')\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    
    req_txt = urllib.request.Request(
        f"{BACKEND_BASE}/api/scan",
        data=body_txt,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req_txt) as resp:
            record("AC5.3 Non-zip text file rejection", False, f"Unexpected success: HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        record("AC5.3 Non-zip text file rejected with HTTP 400", e.code == 400, f"HTTP {e.code}: {e.read().decode('utf-8')}")

    # Non-zip upload via proxy port 3000
    print("\n[Test AC5.4] Non-zip upload via proxy (port 3000)...")
    req_txt_proxy = urllib.request.Request(
        f"{FRONTEND_PROXY_BASE}/api/scan",
        data=body_txt,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req_txt_proxy) as resp:
            record("AC5.4 Proxy non-zip rejection", False, f"Unexpected success: HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        record("AC5.4 Proxy rejects non-zip with HTTP 400", e.code == 400, f"HTTP {e.code}")

    # 4. Oversized upload rejection (HTTP 413)
    print("\n[Test AC5.5] Oversized archive upload rejection via proxy (Content-Length > 650MB)...")
    try:
        oversized_req = urllib.request.Request(
            f"{FRONTEND_PROXY_BASE}/api/scan",
            data=b"0" * 1024,
            headers={
                "Content-Type": "multipart/form-data; boundary=----BoundaryOversized",
                "Content-Length": "700000000",  # ~700 MB > 650 MB Nginx limit
            },
        )
        with urllib.request.urlopen(oversized_req) as resp:
            record("AC5.5 Oversized proxy upload rejection", False, f"Unexpected success: HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        record("AC5.5 Nginx proxy rejects oversized upload with HTTP 413", e.code == 413, f"HTTP {e.code} ({e.reason})")

    print("\n[Test AC5.6] Oversized archive upload rejection via backend direct (Content-Length > 600MB)...")
    try:
        backend_oversized_req = urllib.request.Request(
            f"{BACKEND_BASE}/api/scan",
            data=b"0" * 1024,
            headers={
                "Content-Type": "multipart/form-data; boundary=----BoundaryOversized",
                "Content-Length": "650000000",  # 650 MB > 600 MB backend limit
            },
        )
        with urllib.request.urlopen(backend_oversized_req) as resp:
            record("AC5.6 Oversized backend direct rejection", False, f"Unexpected success: HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        record("AC5.6 Backend direct rejects oversized upload with HTTP 400 or 413", e.code in (400, 413), f"HTTP {e.code} ({e.reason})")

    # 5. Adversarial Malicious Archives (Zip Slip)
    zip_slip_path = FIXTURES_DIR / "zip_slip.zip"
    if zip_slip_path.exists():
        print(f"\n[Test AC5.7] Testing malicious fixture: zip_slip.zip...")
        adv_status, adv_upload = upload_zip(BACKEND_BASE, zip_slip_path)
        adv_job_id = adv_upload.get("job_id")
        if adv_status == 200 and adv_job_id:
            adv_job = poll_job(BACKEND_BASE, adv_job_id, max_wait=40)
            record(
                "AC5.7 Zip-slip defense blocks traversal",
                adv_job.get("status") == "failed",
                f"Final status: {adv_job.get('status')}, Error: {adv_job.get('error')}",
            )

    return clean_job_id, cor_job_id


# ==============================================================================
# SECTION 2: ACCEPTANCE CRITERION 6 CHALLENGES
# ==============================================================================
def challenge_ac6_export_all_formats(vuln_job_id: str, clean_job_id: str, corrupt_job_id: str):
    print("\n" + "="*70)
    print("CHALLENGE AC-6: Live Export Verification Across All 4 Formats")
    print("="*70)

    formats = [
        ("json", "application/json", None),
        ("sarif", "application/sarif+json", None),
        ("html", "text/html; charset=utf-8", b"<!DOCTYPE html>"),
        ("pdf", "application/pdf", b"%PDF-"),
    ]

    # --- 1. Exports on Vulnerable Job (4 findings) ---
    print(f"\n--- Testing Exports on Vulnerable Job ({vuln_job_id}) ---")
    for fmt, expected_mime, magic in formats:
        # Direct backend (port 8000)
        b_status, b_headers, b_content = get_export(BACKEND_BASE, vuln_job_id, fmt)
        record(f"AC6.1 Backend {fmt.upper()} export status 200", b_status == 200, f"Status: {b_status}")
        record(f"AC6.1 Backend {fmt.upper()} Content-Type is '{expected_mime}'", expected_mime in b_headers.get("content-type", ""), f"Content-Type: {b_headers.get('content-type')}")
        expected_filename = f'securescan-report-{vuln_job_id}.{fmt}'
        record(f"AC6.1 Backend {fmt.upper()} Content-Disposition filename", expected_filename in b_headers.get("content-disposition", ""), f"Header: {b_headers.get('content-disposition')}")

        if magic:
            record(f"AC6.1 Backend {fmt.upper()} magic bytes match", b_content.startswith(magic), f"Starts with: {b_content[:15]}")

        # Proxy port 3000
        p_status, p_headers, p_content = get_export(FRONTEND_PROXY_BASE, vuln_job_id, fmt)
        record(f"AC6.2 Proxy {fmt.upper()} export status 200", p_status == 200, f"Status: {p_status}")
        record(f"AC6.2 Proxy {fmt.upper()} Content-Type matches", expected_mime in p_headers.get("content-type", ""), f"Proxy Content-Type: {p_headers.get('content-type')}")
        if magic:
            record(f"AC6.2 Proxy {fmt.upper()} magic bytes match", p_content.startswith(magic), f"Starts with: {p_content[:15]}")

        # Deep payload validation
        if fmt == "json":
            try:
                j = json.loads(b_content.decode("utf-8"))
                has_keys = all(k in j for k in ["schemaVersion", "job_id", "summary", "findings"])
                finding_count = len(j.get("findings", []))
                record("AC6.3 JSON structure conforms to schema", has_keys and finding_count == 4, f"Keys: {list(j.keys())}, Findings: {finding_count}")
            except Exception as e:
                record("AC6.3 JSON structure conforms to schema", False, str(e))

        elif fmt == "sarif":
            try:
                s = json.loads(b_content.decode("utf-8"))
                sarif_ver = s.get("version")
                runs = s.get("runs", [])
                results = runs[0].get("results", []) if runs else []
                record("AC6.4 SARIF conforms to OASIS SARIF 2.1.0", sarif_ver == "2.1.0" and len(results) == 4, f"Version: {sarif_ver}, Runs: {len(runs)}, Results: {len(results)}")
            except Exception as e:
                record("AC6.4 SARIF conforms to OASIS SARIF 2.1.0", False, str(e))

        elif fmt == "html":
            html_text = b_content.decode("utf-8")
            has_doct = html_text.startswith("<!DOCTYPE html>")
            has_pickle = "pickle" in html_text.lower()
            has_eval = "eval" in html_text.lower()
            record("AC6.5 Standalone HTML contains findings & markup", has_doct and has_pickle and has_eval, f"Size: {len(b_content)} bytes")

        elif fmt == "pdf":
            # Check PDF version and content size
            pdf_magic = b_content[:8].decode("latin-1", errors="ignore")
            ends_eof = b_content.strip().endswith(b"%%EOF")
            record("AC6.6 Binary PDF valid and non-empty", b_content.startswith(b"%PDF-") and len(b_content) > 5000 and ends_eof, f"Magic: {pdf_magic}, Length: {len(b_content)} bytes, ends with %%EOF: {ends_eof}")

    # --- 2. Exports on Clean Job (0 findings) ---
    print(f"\n--- Testing Exports on Clean Job ({clean_job_id}) ---")
    for fmt, expected_mime, magic in formats:
        status, headers, content = get_export(BACKEND_BASE, clean_job_id, fmt)
        record(f"AC6.7 Clean export {fmt.upper()} status 200", status == 200, f"Status: {status}, Size: {len(content)} bytes")
        if fmt == "json":
            j = json.loads(content.decode("utf-8"))
            record("AC6.7 Clean JSON has 0 findings", len(j.get("findings", [])) == 0, f"Findings: {len(j.get('findings', []))}")
        elif fmt == "sarif":
            s = json.loads(content.decode("utf-8"))
            results = s.get("runs", [{}])[0].get("results", [])
            record("AC6.7 Clean SARIF has 0 results", len(results) == 0, f"Results: {len(results)}")

    # --- 3. Adversarial / Edge Cases on Export Endpoints ---
    print("\n--- Testing Export Endpoint Edge Cases & Defenses ---")
    
    # 3.1 Unsupported format
    status, _, body = get_export(BACKEND_BASE, vuln_job_id, "xml")
    record("AC6.8 Unsupported format 'xml' rejected with HTTP 400", status == 400, f"Status: {status}")

    status, _, body = get_export(BACKEND_BASE, vuln_job_id, "exe")
    record("AC6.8 Unsupported format 'exe' rejected with HTTP 400", status == 400, f"Status: {status}")

    # 3.2 Non-existent job
    status, _, body = get_export(BACKEND_BASE, "00000000-0000-0000-0000-000000000000", "json")
    record("AC6.9 Non-existent job rejected with HTTP 404", status == 404, f"Status: {status}")

    # 3.3 Export on failed scan (corrupt job)
    status, _, body = get_export(BACKEND_BASE, corrupt_job_id, "json")
    record("AC6.10 Export on failed job returns HTTP 422", status == 422, f"Status: {status}")

    # 3.4 Case insensitivity on format query parameter
    for case_fmt in ["JSON", "Sarif", "HtMl", "PDF"]:
        status, _, content = get_export(BACKEND_BASE, vuln_job_id, case_fmt)
        record(f"AC6.11 Format case-insensitivity for '{case_fmt}'", status == 200 and len(content) > 0, f"Status: {status}")


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================
if __name__ == "__main__":
    print("\n" + "#"*70)
    print("STARTING EMPIRICAL CHALLENGER VERIFICATION (M3 GATE: AC-5 & AC-6)")
    print("#"*70)
    t0 = time.time()

    # Determine or run vulnerable scan job for export testing
    vuln_path = FIXTURES_DIR / "valid_vulnerable.zip"
    print(f"\nUploading {vuln_path.name} to obtain guaranteed scan job...")
    v_status, v_upload = upload_zip(BACKEND_BASE, vuln_path)
    assert v_status == 200, f"Vulnerable upload failed: {v_status}, {v_upload}"
    vuln_job_id = v_upload["job_id"]
    print(f"Vulnerable scan job queued: {vuln_job_id}")
    print("Polling vulnerable scan job to completion...")
    v_job = poll_job(BACKEND_BASE, vuln_job_id, max_wait=180)
    assert v_job.get("status") == "done", f"Job failed: {v_job}"
    print(f"Vulnerable scan completed in status '{v_job.get('status')}'!")

    # Verify findings count on vulnerable job
    vr_status, v_rep = get_report(BACKEND_BASE, vuln_job_id)
    assert vr_status == 200 and len(v_rep.get("findings", [])) == 4, f"Expected 4 findings, got: {v_rep}"
    print(f"Confirmed 4 findings detected in {vuln_job_id}: {[f.get('rule_id') for f in v_rep.get('findings', [])]}")

    # Challenge AC-5
    clean_job_id, corrupt_job_id = challenge_ac5_benign_and_edge_cases()

    # Challenge AC-6
    challenge_ac6_export_all_formats(vuln_job_id, clean_job_id, corrupt_job_id)

    # Summary
    duration = round(time.time() - t0, 2)
    total_tests = len(test_results)
    passed_tests = sum(1 for t in test_results if t["passed"])
    failed_tests = total_tests - passed_tests

    print("\n" + "="*70)
    print(f"CHALLENGER M3_2 VERIFICATION RESULTS SUMMARY ({duration}s)")
    print("="*70)
    print(f"Total Tests Executed: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")

    if failed_tests > 0:
        print("\nFAILED TESTS:")
        for t in test_results:
            if not t["passed"]:
                print(f"  - {t['test']}: {t['details']}")
        sys.exit(1)
    else:
        print("\nALL EMPIRICAL CHALLENGES PASSED WITH ZERO FAILURES!")
        sys.exit(0)
