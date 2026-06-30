#!/usr/bin/env python3
"""
free-for-dev JSON Generator

Generates free-for-dev.json and free-for-dev.min.json from README.md.

Usage:
  python3 generate-json.py [--input README.md] [--output-dir .]

The JSON schema:
{
  "meta": { "name", "description", "source", "category_count", "service_count" },
  "categories": [
    {
      "section": "Category Name",
      "services": [
        {
          "name": "Service Name",
          "url": "https://...",
          "description": "Free tier details...",
          "features": ["sub-item 1", "sub-item 2"]  // optional, for cloud providers etc.
        }
      ]
    }
  ]
}
"""
import re, json, os, sys

def parse_readme(text: str) -> dict:
    section_pat = re.compile(r'^## (.+)$')
    entry2_pat = re.compile(r'^  \* \[([^\]]+)\]\(([^)]+)\)(?: - (.*))?$')
    entry0_pat = re.compile(r'^\* \[([^\]]+)\]\(([^)]+)\)(?: - (.*))?$')
    sub_pat = re.compile(r'^    \* (.*)$')
    back_pat = re.compile(r'\[⬆|\[Back to top\]', re.I)

    sections = []
    cur_sec = None
    cur_svc = None

    def flush_service():
        nonlocal cur_svc
        if cur_svc and (cur_svc['subs'] or cur_svc['description']):
            sections[-1]['services'].append({
                'name': cur_svc['name'],
                'url': cur_svc['url'],
                'description': cur_svc['description'],
                **({'features': cur_svc['subs']} if cur_svc['subs'] else {})
            })
        cur_svc = None

    def flush_services():
        flush_service()

    for line in text.split('\n'):
        if back_pat.search(line):
            flush_services()
            continue
        m = section_pat.match(line)
        if m:
            flush_services()
            cur_sec = m.group(1).strip()
            if cur_sec == 'Table of Contents':
                cur_sec = None
                continue
            sections.append({'section': cur_sec, 'services': []})
            continue
        m = entry2_pat.match(line) or entry0_pat.match(line)
        if m:
            flush_service()
            cur_svc = {
                'name': m.group(1).strip(),
                'url': m.group(2).strip(),
                'description': (m.group(3) or '').strip(),
                'subs': []
            }
            continue
        m = sub_pat.match(line)
        if m and cur_svc:
            sub_text = m.group(1).strip()
            if sub_text:
                cur_svc['subs'].append(sub_text)
            continue
        if cur_svc and line.strip() and not line.startswith('#') and not line.startswith('['):
            if line.startswith('  ') and not line.startswith('    *'):
                text = line.strip()
                if text:
                    if cur_svc['description'] and not cur_svc['description'].endswith(' '):
                        cur_svc['description'] += ' '
                    cur_svc['description'] += text

    flush_services()
    return sections

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate free-for-dev JSON from README.md')
    parser.add_argument('--input', default='README.md', help='Input README.md path')
    parser.add_argument('--output-dir', default='.', help='Output directory for JSON files')
    args = parser.parse_args()

    with open(args.input) as f:
        text = f.read()

    sections = parse_readme(text)
    total_services = sum(len(c['services']) for c in sections)
    total_subs = sum(len(s.get('features', [])) for c in sections for s in c['services'])

    output = {
        'meta': {
            'name': 'free-for.dev',
            'description': 'List of software (SaaS, PaaS, IaaS, etc.) with free developer tiers',
            'source': 'https://github.com/ripienaar/free-for-dev',
            'category_count': len(sections),
            'service_count': total_services,
            'feature_count': total_subs
        },
        'categories': sections
    }

    json_path = os.path.join(args.output_dir, 'free-for-dev.json')
    min_path = os.path.join(args.output_dir, 'free-for-dev.min.json')

    with open(json_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    with open(min_path, 'w') as f:
        json.dump(output, f, separators=(',', ':'), ensure_ascii=False)

    print(f'Generated: {json_path}')
    print(f'Generated: {min_path}')
    print(f'Categories: {len(sections)}, Services: {total_services}, Features: {total_subs}')

if __name__ == '__main__':
    main()
