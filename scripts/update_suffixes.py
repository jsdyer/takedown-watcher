#!/usr/bin/env python3
"""Refresh the bundled ICANN registration boundaries; run no more than daily."""
import hashlib,json,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
URL='https://publicsuffix.org/list/public_suffix_list.dat'
with urllib.request.urlopen(URL,timeout=30) as response:
    raw=response.read(1000001)
if len(raw)>1000000: raise ValueError('Suffix list exceeds size limit')
text=raw.decode(); section=text.split('// ===BEGIN ICANN DOMAINS===')[1].split('// ===END ICANN DOMAINS===')[0]
rules=[]
for line in section.splitlines():
    rule=line.split('//')[0].strip()
    if not rule: continue
    prefix='!' if rule.startswith('!') else '*.' if rule.startswith('*.') else ''
    rules.append(prefix+rule[len(prefix):].encode('idna').decode('ascii').lower())
if len(rules)<1000: raise ValueError('Incomplete suffix list; retained existing snapshot')
version=next(line.split(':',1)[1].strip() for line in text.splitlines() if line.startswith('// VERSION:'))
data={'source':URL,'version':version,'license':'Mozilla Public License 2.0','scope':'ICANN domains only: registration boundary, not a hosted-service tenant boundary','source_sha256':hashlib.sha256(raw).hexdigest(),'rules':rules}
(ROOT/'web/vendor/public-suffixes.json').write_text(json.dumps(data,ensure_ascii=False,indent=1)+'\n')
print('Updated',len(rules),'ICANN rules from',version)
