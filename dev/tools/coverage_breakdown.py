#!/usr/bin/env python3
"""Generate coverage breakdown by RFC."""

import json

with open('/workspace/spec/requirements-atomic.json', 'r') as f:
    data = json.load(f)

# Group by RFC
by_rfc = {}
for req in data['atomic_requirements']:
    source = req['source']
    if source not in by_rfc:
        by_rfc[source] = {'total': 0, 'covered': 0, 'out_of_scope': 0}
    by_rfc[source]['total'] += 1
    if req.get('out_of_scope'):
        by_rfc[source]['out_of_scope'] += 1
    if req['state'] != 'not_started':
        by_rfc[source]['covered'] += 1

# Print breakdown
print("Coverage Breakdown by RFC:")
print("=" * 60)
for source in sorted(by_rfc.keys()):
    stats = by_rfc[source]
    pct_total = round(stats['covered'] / stats['total'] * 100, 1) if stats['total'] > 0 else 0.0
    in_scope_count = stats['total'] - stats['out_of_scope']
    pct_in_scope = round(stats['covered'] / in_scope_count * 100, 1) if in_scope_count > 0 else 0.0
    
    if stats['out_of_scope'] > 0:
        print(f"{source:20} {stats['covered']:3}/{stats['total']:3} ({pct_total:5.1f}%)  {stats['covered']:3}/{in_scope_count:3} in-scope ({pct_in_scope:5.1f}%)")
    else:
        print(f"{source:20} {stats['covered']:3}/{stats['total']:3} ({pct_total:5.1f}%)")

print("=" * 60)
total = sum(s['total'] for s in by_rfc.values())
covered = sum(s['covered'] for s in by_rfc.values())
out_of_scope_total = sum(s['out_of_scope'] for s in by_rfc.values())
in_scope_total = total - out_of_scope_total
pct_total = round(covered / total * 100, 1) if total > 0 else 0.0
pct_in_scope = round(covered / in_scope_total * 100, 1) if in_scope_total > 0 else 0.0
print(f"{'TOTAL':20} {covered:3}/{total:3} ({pct_total:5.1f}%)  {covered:3}/{in_scope_total:3} in-scope ({pct_in_scope:5.1f}%)")
