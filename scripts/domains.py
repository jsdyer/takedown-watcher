"""ICANN registration boundary from the bundled Public Suffix List."""
import json
from pathlib import Path
RULES=set(json.loads((Path(__file__).resolve().parents[1]/'web/vendor/public-suffixes.json').read_text())['rules'])
def registered_domain(host):
    labels=host.lower().rstrip('.').split('.')
    count=1
    for i in range(len(labels)):
        tail='.'.join(labels[i:])
        if '!'+tail in RULES:
            count=len(labels)-i-1; break
        if tail in RULES: count=max(count,len(labels)-i)
        if i+1<len(labels) and '*.'+'.'.join(labels[i+1:]) in RULES: count=max(count,len(labels)-i)
    return '.'.join(labels[-count-1:]) if len(labels)>count else None
