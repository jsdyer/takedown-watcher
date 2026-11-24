// Public Suffix List ICANN rules. The registration boundary is independent of hosted-service tenants.
import snapshot from './vendor/public-suffixes.json' with { type: 'json' };
const rules = new Set(snapshot.rules);
export function registeredDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  let count = 1;
  for (let i = 0; i < labels.length; i += 1) {
    const tail = labels.slice(i).join('.');
    if (rules.has('!' + tail)) { count = labels.length - i - 1; break; }
    if (rules.has(tail)) count = Math.max(count, labels.length - i);
    if (i + 1 < labels.length && rules.has('*.' + labels.slice(i + 1).join('.'))) count = Math.max(count, labels.length - i);
  }
  return labels.length > count ? labels.slice(-count - 1).join('.') : null;
}
