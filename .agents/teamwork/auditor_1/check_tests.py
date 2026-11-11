import os

test_dirs = ['backend/tests', 'tests']
skip_keywords = ['skip', 'xfail', 'ignore', 'pass']

print("=== Scanning test suites for skip / xfail / suppression patterns ===")
hits = []
for tdir in test_dirs:
    if not os.path.exists(tdir):
        continue
    for root, dirs, files in os.walk(tdir):
        for f in files:
            if f.endswith('.py'):
                fpath = os.path.join(root, f)
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                    for i, line in enumerate(fp, 1):
                        stripped = line.strip()
                        if stripped.startswith(('@pytest.mark.skip', '@pytest.mark.xfail', 'pytest.skip', 'pytest.xfail')):
                            hits.append((fpath, i, stripped))

print(f"Total skipped/xfailed test markers found: {len(hits)}")
for fpath, line_no, text in hits:
    print(f"{fpath}:{line_no}: {text}")
