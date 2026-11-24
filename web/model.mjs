// Pure functions for the takedown watcher page. No DOM access here.

export const STATES = {
  live: { label: 'Live', tone: 'bad', text: 'Site is up and serving content' },
  'cdn-warning': { label: 'CDN warning', tone: 'mid', text: 'Cloudflare is showing a phishing warning in front of the site' },
  suspended: { label: 'Suspended', tone: 'good', text: 'The host replaced the site with a suspension page' },
  'http-error': { label: 'HTTP error', tone: 'mid', text: 'The server answers, but with an error status' },
  unreachable: { label: 'Unreachable', tone: 'mid', text: 'The domain resolves, but nothing answers at that address' },
  'no-address': { label: 'No address', tone: 'good', text: 'The domain exists, but has no IP address in DNS' },
  nxdomain: { label: 'NXDOMAIN', tone: 'good', text: 'The domain no longer resolves' },
  hold: { label: 'On hold', tone: 'good', text: 'The registrar or registry put the domain on hold' },
  deleted: { label: 'Deleted', tone: 'good', text: 'The domain is no longer registered' },
};

const DOWN = new Set(Object.keys(STATES).filter(state => state !== 'live'));
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;

export function stateInfo(state) {
  return STATES[state] ?? { label: state ?? 'Unknown', tone: 'mid', text: 'Unrecognized state' };
}

export function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '';
  const hours = ms / 3_600_000;
  if (hours < 1) return `${Math.max(1, Math.round(ms / 60_000))} min`;
  if (hours < 48) return `${Math.round(hours)} h`;
  return `${Math.round(hours / 24)} days`;
}

function reportedAt(record) {
  return record.reported ? Date.parse(`${record.reported}T00:00:00Z`) : NaN;
}

// The first change from live (or from the start) to a down state, at or after the report date.
export function firstTakedown(record) {
  const reported = reportedAt(record);
  const changes = record.changes ?? [];
  for (let i = 0; i < changes.length; i += 1) {
    const change = changes[i];
    if (!DOWN.has(change.state)) continue;
    const at = Date.parse(change.at);
    if (Number.isFinite(reported) && at < reported) continue;
    const wasLive = i > 0 && changes[i - 1].state === 'live';
    return { at: change.at, state: change.state, actor: change.actor ?? null, observedLiveBefore: wasLive,
      afterReport: Number.isFinite(reported) ? formatDuration(at - reported) : '' };
  }
  return null;
}

export function summarize(history, { includeUnwatched = false } = {}) {
  if (!history || typeof history !== 'object' || typeof history.targets !== 'object') {
    throw new TypeError('Unexpected history data');
  }
  const rows = Object.values(history.targets)
    .filter(record => includeUnwatched || record.watched !== false)
    .map(record => {
      const current = record.current ?? {};
      const last = (record.changes ?? []).at(-1);
      return {
        target: record.target,
        url: record.url ?? null,
        watched: record.watched !== false,
        reported: record.reported ?? null,
        note: record.note ?? null,
        state: current.state ?? null,
        actor: current.actor ?? null,
        since: last?.at ?? null,
        lastChecked: record.last_checked ?? null,
        lastError: record.last_error ?? null,
        takedown: firstTakedown(record),
        current,
        changes: record.changes ?? [],
      };
    });
  const order = state => (state === 'live' ? 0 : state ? 1 : 2);
  rows.sort((a, b) => order(a.state) - order(b.state) || a.target.localeCompare(b.target));
  const counts = {};
  for (const row of rows) counts[row.state ?? 'unchecked'] = (counts[row.state ?? 'unchecked'] ?? 0) + 1;
  return { rows, counts, lastRun: history.last_run ?? null,
    unwatched: Object.values(history.targets).filter(r => r.watched === false).length };
}

// ---- Instant check in the browser (keyless sources only) ----

export function parseTarget(input) {
  const raw = String(input ?? '').trim();
  if (!raw) throw new Error('Enter a domain or URL');
  let host;
  try {
    host = new URL(raw.includes('://') ? raw : `https://${raw}`).hostname;
  } catch {
    throw new Error('That is not a valid domain or URL');
  }
  host = host.replace(/\.$/, '').toLowerCase();
  if (!HOST.test(host)) throw new Error('That is not a valid domain name');
  return host;
}

export function registeredDomain(host, multiLabel = ['co.uk', 'org.uk', 'com.au', 'co.nz', 'co.jp', 'gc.ca']) {
  const labels = host.split('.');
  if (labels.length >= 3 && multiLabel.includes(labels.slice(-2).join('.'))) return labels.slice(-3).join('.');
  return labels.slice(-2).join('.');
}

export function parseDoh(data, type) {
  if (!data || typeof data.Status !== 'number') throw new Error('Unexpected DNS response');
  const rcode = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' }[data.Status] ?? `RCODE${data.Status}`;
  const wanted = type === 'AAAA' ? 28 : 1;
  const addresses = (data.Answer ?? []).filter(a => a.type === wanted).map(a => a.data);
  return { rcode, addresses: [...new Set(addresses)].sort() };
}

function vcard(entity, field) {
  const card = entity?.vcardArray?.[1];
  if (!Array.isArray(card)) return null;
  const item = card.find(entry => Array.isArray(entry) && entry[0] === field);
  if (!item) return null;
  return Array.isArray(item[3]) ? item[3][0] : item[3];
}

function* entities(list, role) {
  for (const entity of list ?? []) {
    if (entity?.roles?.includes(role)) yield entity;
    yield* entities(entity?.entities, role);
  }
}

export function parseRdap(data) {
  const registrar = entities(data?.entities, 'registrar').next().value;
  const abuse = registrar ? entities(registrar.entities, 'abuse').next().value : undefined;
  const events = Object.fromEntries((data?.events ?? []).map(e => [e.eventAction, e.eventDate]));
  return {
    found: true,
    statuses: [...new Set((data?.status ?? []).map(s => String(s).toLowerCase()))].sort(),
    registrar: registrar ? vcard(registrar, 'fn') : null,
    registrarAbuse: abuse ? String(vcard(abuse, 'email') ?? '').replace(/^mailto:/, '') || null : null,
    registered: events.registration ?? null,
    expires: events.expiration ?? null,
  };
}

// The browser cannot fetch the site itself (cross-origin), so this stops at DNS and registration.
export function quickState(dns, rdap) {
  if (rdap && rdap.found === false) return 'deleted';
  if (rdap?.statuses?.some(s => s === 'client hold' || s === 'server hold')) return 'hold';
  if (dns.rcode === 'NXDOMAIN') return 'nxdomain';
  if (!dns.addresses.length) return 'no-address';
  return 'resolves';
}
