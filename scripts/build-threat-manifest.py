#!/usr/bin/env python3
"""Scan docs/threats/*.md, extract YAML frontmatter, write manifest.json."""

import json
import os
import re
import sys

THREATS_DIR = os.path.join(os.path.dirname(__file__), '..', 'docs', 'threats')
OUT = os.path.join(THREATS_DIR, 'manifest.json')

FM_RE = re.compile(r'^---\n(.*?)\n---', re.S)
KV_RE = re.compile(r'^(\w[\w_]*):\s*"?(.*?)"?\s*$', re.M)


def extract_frontmatter(path):
    with open(path) as f:
        text = f.read()
    m = FM_RE.match(text)
    if not m:
        return None
    return dict(KV_RE.findall(m.group(1)))


def main():
    entries = []
    for fname in sorted(os.listdir(THREATS_DIR)):
        if not fname.endswith('.md'):
            continue
        meta = extract_frontmatter(os.path.join(THREATS_DIR, fname))
        if not meta or 'id' not in meta:
            print(f'WARN: skipping {fname} (no frontmatter/id)', file=sys.stderr)
            continue
        entries.append({
            'id': meta['id'],
            'title': meta.get('title', ''),
            'file': fname,
            'difficulty': meta.get('detection_difficulty', 'medium'),
            'category_id': meta.get('category_id', meta['id'][0]),
            'description': meta.get('description', ''),
        })

    with open(OUT, 'w') as f:
        json.dump(entries, f, indent=2)
        f.write('\n')

    print(f'Wrote {len(entries)} threats to {OUT}')


if __name__ == '__main__':
    main()
