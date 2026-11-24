import { STATES, stateInfo, summarize, parseTarget, registeredDomain, parseDoh, parseRdap, quickState } from './model.mjs';

const $ = selector => document.querySelector(selector);
let history = null;
let checkRun = 0;

function el(tag, text, attrs = {}) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

function when(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.valueOf()) ? iso : date.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function badge(state) {
  const info = stateInfo(state);
  return el('span', info.label, { class: `badge ${info.tone}`, title: info.text });
}

function fact(list, term, value) {
  if (value == null || value === '' || (Array.isArray(value) && !value.length)) return;
  list.append(el('dt', term), el('dd', Array.isArray(value) ? value.join(', ') : String(value)));
}

function renderDetails(row) {
  const box = $('#details');
  box.replaceChildren();
  const article = el('article', null, { class: 'detail', 'aria-labelledby': 'detail-title' });
  article.append(el('h3', row.target, { id: 'detail-title' }));
  const facts = el('dl', null, { class: 'facts' });
  const c = row.current;
  fact(facts, 'Checked URL', row.url);
  fact(facts, 'Note', row.note);
  fact(facts, 'DNS', c.dns ? `${c.dns.status}${c.dns.a?.length || c.dns.aaaa?.length ? ' → ' + [...(c.dns.a ?? []), ...(c.dns.aaaa ?? [])].join(', ') : ''}` : null);
  fact(facts, 'Network', c.network?.asn ? `${c.network.asn} ${c.network.as_name ?? ''} (${c.network.country_code ?? '?'})` : null);
  fact(facts, 'Registrar', c.rdap?.registrar);
  fact(facts, 'Registrar abuse contact', c.rdap?.registrar_abuse);
  fact(facts, 'Registry status', c.rdap?.statuses);
  fact(facts, 'Registered', c.rdap?.registered ? when(c.rdap.registered) : null);
  fact(facts, 'Nameservers', c.rdap?.nameservers);
  fact(facts, 'HTTP', c.http ? (c.http.error ?? `${c.http.status}${c.http.title ? ` · “${c.http.title}”` : ''}`) : null);
  fact(facts, 'Behind Cloudflare', c.http?.cloudflare ? 'Yes — report to Cloudflare as well as the origin host' : null);
  fact(facts, 'Certificate problem', c.http?.tls_error);
  fact(facts, 'AbuseIPDB', c.reputation ? `confidence ${c.reputation.score}% · ${c.reputation.reports} reports` : null);
  fact(facts, 'Last check failed', row.lastError ? `${when(row.lastError.at)}: ${row.lastError.error}` : null);
  article.append(facts, el('h4', 'Timeline'));
  const list = el('ol', null, { class: 'timeline' });
  if (row.reported) {
    const item = el('li');
    item.append(el('time', row.reported), ' Reported');
    list.append(item);
  }
  for (const change of row.changes) {
    const item = el('li');
    item.append(el('time', when(change.at), { datetime: change.at }), ' ', badge(change.state));
    if (change.actor) item.append(` · recorded role: ${change.actor}`);
    if (change.scan && /^https:\/\/urlscan\.io\/result\/[a-zA-Z0-9-]+\/?$/.test(change.scan)) {
      item.append(' · ');
      item.append(el('a', 'urlscan evidence', { href: change.scan, rel: 'noreferrer noopener' }));
    }
    list.append(item);
  }
  article.append(list);
  box.append(article);
}

function render() {
  const { rows, lastRun, unwatched } = summarize(history, { includeUnwatched: $('#show-removed').checked });
  $('#run-info').textContent = lastRun
    ? `Last capture: ${when(lastRun)}. ${rows.length} ${rows.length === 1 ? 'target' : 'targets'} shown${unwatched ? `, ${unwatched} removed from the watchlist` : ''}.`
    : 'No capture has run yet.';
  $('#empty').hidden = rows.length > 0;
  const body = $('#targets tbody');
  body.replaceChildren();
  for (const row of rows) {
    const tr = el('tr');
    const cell = el('td');
    const button = el('button', row.target, { type: 'button', class: 'link' });
    button.addEventListener('click', () => renderDetails(row));
    cell.append(button);
    if (row.note) cell.append(el('p', row.note, {class:'muted small'}));
    if (row.lastError) cell.append(el('p', 'Latest check failed; showing the previous observation', {class:'muted small'}));
    if (!row.watched) cell.append(el('span', ' (removed)', { class: 'muted' }));
    const stateCell = el('td');
    stateCell.append(row.state ? badge(row.state) : el('span', 'Not checked', { class: 'muted' }));
    tr.append(cell, stateCell, el('td', row.state === 'hold' ? row.actor ?? '—' : 'Unconfirmed'), el('td', row.reported ?? '—'),
      el('td', row.takedown ? '~' + row.takedown.afterReport : '—'), el('td', when(row.lastChecked)));
    body.append(tr);
  }
  $('#targets').hidden = rows.length === 0;
}

function renderLegend() {
  const list = $('#legend');
  for (const [state, info] of Object.entries(STATES)) {
    const dt = el('dt');
    dt.append(badge(state));
    list.append(dt, el('dd', info.text));
  }
}

async function getJson(url, accept = 'application/json') {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, { headers: { Accept: accept }, credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal });
    return { status: response.status, data: response.status === 200 ? await response.json() : null };
  } finally { clearTimeout(timer); }
}

async function instantCheck(event) {
  event.preventDefault();
  const run = ++checkRun;
  const status = $('#check-status');
  const result = $('#check-result');
  result.hidden = true;
  let host;
  try {
    host = parseTarget($('#check-input').value);
  } catch (error) {
    status.textContent = error.message;
    return;
  }
  status.textContent = `Checking ${host}…`;
  try {
    if (!registeredDomain(host)) throw new Error('Enter a registered domain');
    const dnsUrl = type => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
    const [a, aaaa, rdapResponse] = await Promise.all([
      getJson(dnsUrl('A'), 'application/dns-json'),
      getJson(dnsUrl('AAAA'), 'application/dns-json'),
      getJson(`https://rdap.org/domain/${encodeURIComponent(registeredDomain(host))}`, 'application/rdap+json').catch(() => ({status:0,data:null})),
    ]);
    if (run !== checkRun) return;
    const v4 = parseDoh(a.data, 'A');
    const v6 = parseDoh(aaaa.data, 'AAAA');
    const dns = { rcode: v4.rcode !== 'NOERROR' ? v4.rcode : v6.rcode, addresses: [...v4.addresses, ...v6.addresses] };
    const rdap = rdapResponse.status === 404 ? { found: false } : rdapResponse.data ? parseRdap(rdapResponse.data) : null;
    const state = quickState(dns, rdap);
    result.replaceChildren();
    fact(result, 'Result', state === 'resolves' ? 'DNS has an address. This browser check does not establish whether the site is online.' : stateInfo(state).text);
    fact(result, 'DNS', `${dns.rcode}${dns.addresses.length ? ' → ' + dns.addresses.join(', ') : ''}`);
    if (rdap?.found) {
      fact(result, 'Registrar', rdap.registrar);
      fact(result, 'Registrar abuse contact', rdap.registrarAbuse);
      fact(result, 'Registry status', rdap.statuses);
      fact(result, 'Registered', rdap.registered ? when(rdap.registered) : null);
    } else {
      fact(result, 'Registration', rdap?.found === false ? 'RDAP returned no record; this does not prove deletion.' : 'RDAP lookup unavailable; DNS results are shown separately.');
    }
    result.hidden = false;
    status.textContent = `Checked ${host} at ${when(new Date().toISOString())}.`;
  } catch {
    if (run !== checkRun) return;
    status.textContent = 'The lookup failed. Your network or a browser extension may be blocking it; try again.';
  }
}

renderLegend();
$('#check-form').addEventListener('submit', instantCheck);
$('#show-removed').addEventListener('change', () => history && render());
try {
  const response = await fetch('./data/history.json', { cache: 'no-cache' });
  if (!response.ok) throw new Error(String(response.status));
  history = await response.json();
  render();
} catch {
  $('#run-info').textContent = 'The capture file could not be loaded.';
}
