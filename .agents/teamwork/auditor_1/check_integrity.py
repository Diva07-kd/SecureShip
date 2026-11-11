import os
import re

search_dirs = ['backend/app', 'frontend/src']
keywords = [
    'mock', 'dummy', 'fake', 'hardcoded', 'stub',
    'is_test', 'testing', 'pytest', 'sys.argv', 'test_mode',
    'return true', 'return false', 'return []', 'return {}'
]

print("=== Scanning backend/app and frontend/src for suspicious patterns ===")
hits = []
for sdir in search_dirs:
    for root, dirs, files in os.walk(sdir):
        for f in files:
            if f.endswith(('.py', '.ts', '.tsx')):
                fpath = os.path.join(root, f)
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                    for i, line in enumerate(fp, 1):
                        low = line.lower()
                        for kw in keywords:
                            if kw in low:
                                hits.append((fpath, i, kw, line.strip()))

print(f"Total matching lines found: {len(hits)}")
for fpath, line_no, kw, text in hits:
    print(f"{fpath}:{line_no} [{kw}]: {text[:120]}")
