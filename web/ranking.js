'use strict';

function isLocalAddress(row) {
  return (row.notes || []).some(note => note.startsWith('Служебный/непубличный адрес:'));
}

function resultStatus(row) {
  if (row.error || row.status === 'error') return 'error';
  if (row.status === 'suspicious' && isLocalAddress(row) &&
      !(row.notes || []).some(note => note.startsWith('NXDOMAIN расходится'))) return 'local';
  if (row.status === 'insufficient' && row.rcode === 'NOERROR' && row.dnssec === 'no_signature'
      && (row.ips || []).length > 0 && !isLocalAddress(row)) return 'received';
  return row.status;
}

function isTimeout(row) {
  return !!row.error && /timeout|timed? out|deadline exceeded|таймаут/i.test(row.error);
}

function latencyMetric(rows) {
  const ms = rows.filter(row => !['error', 'suspicious', 'local'].includes(resultStatus(row)))
    .map(row => row.ms).filter(Number.isFinite).sort((a, b) => a - b);
  const count = ms.length;
  const median = count ? (ms[Math.floor((count - 1) / 2)] + ms[Math.floor(count / 2)]) / 2 : Infinity;
  const label = count >= 20 ? 'p95' : 'p50';
  return {value: label === 'p95' ? ms[Math.ceil(count * .95) - 1] : median, median, count, label};
}

function rankResults(rows) {
  const groups = new Map();
  for (const row of rows) {
    const key = row.server + ' / ' + row.transport.toUpperCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  return [...groups].map(([key, attempts]) => {
    const series = new Map();
    let errors = 0, suspicious = 0, local = 0, timeouts = 0, longest = 0;
    for (const row of attempts) {
      const status = resultStatus(row);
      if (status === 'error') errors++;
      if (status === 'suspicious') suspicious++;
      if (isLocalAddress(row)) local++;
      if (isTimeout(row)) timeouts++;
      const question = row.domain + '/' + row.type;
      const streak = status === 'error' ? (series.get(question) || 0) + 1 : 0;
      series.set(question, streak);
      longest = Math.max(longest, streak);
    }
    const latency = latencyMetric(attempts);
    return {
      key, server: attempts[0].server, transport: attempts[0].transport, count: attempts.length,
      localAddresses: [...new Set(attempts.flatMap(row => (row.notes || [])
        .filter(note => note.startsWith('Служебный/непубличный адрес: '))
        .map(note => note.slice('Служебный/непубличный адрес: '.length).split(';')[0])))],
      received: attempts.filter(row => !row.error).length,
      errors, suspicious, local, timeouts, badRate: (errors + suspicious) / attempts.length,
      latency, longest
    };
  }).sort((a, b) => b.badRate - a.badRate || b.errors / b.count - a.errors / a.count ||
    (a.latency.median === b.latency.median ? 0 : a.latency.median - b.latency.median) ||
    b.count - a.count || a.key.localeCompare(b.key));
}
if (typeof module !== 'undefined') module.exports = {rankResults, latencyMetric, resultStatus};
