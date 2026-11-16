'use strict';

const $ = id => document.getElementById(id);
let endpoints = [], token = '', run = null;
let liveRun = null, viewingHistory = false, selectedOnly = false;
let pathFilter = '', statusFilter = 'all', requestVersion = 0;

const labels = {
  passed: '✓ Подтверждено', error: '✕ Ошибка',
  suspicious: '! Подозрительно', insufficient: '○ Недостаточно данных', local: 'Служебный IP', received: '✓ Ответ получен'
};
const catalogLabels = {
  documented: 'Сверено с источником', partial: 'Есть оговорки',
  outage: 'Сообщение о сбое', unconfirmed: 'Не подтверждено'
};
const dnssecLabels = {
  validated: ['ок', 'Подпись ответа проверена по доверенной цепочке DNSSEC.', 'passed'],
  no_signature: ['без подписи', 'В проверяемом наборе записей нет RRSIG. Это не устанавливает, подписана ли сама зона.', 'insufficient'],
  invalid_signature: ['ошибка подписи', 'Подпись ответа или срок её действия не прошли проверку доверенным ключом.', 'error'],
  indeterminate: ['не подтверждена', 'Не хватило данных для проверки подписи или цепочки DNSSEC.', 'insufficient'],
  not_checked: ['не проверялась', 'Локальная проверка DNSSEC не выполнялась для этого ответа.', 'insufficient']
};
const termHelp = {
  NXDOMAIN: 'По ответу резолвера такого домена не существует.',
  SERVFAIL: 'Резолвер не смог обработать запрос.',
  AD: 'Резолвер сообщает, считает ли он данные подтверждёнными DNSSEC.',
  DOH3: 'DNS через HTTPS по HTTP/3 поверх QUIC.',
  DOQ: 'DNS напрямую через защищённое соединение QUIC.'
};

function node(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (cls) el.className = cls;
  return el;
}

async function api(path, body) {
  const options = body === undefined ? {} : {
    method: 'POST', headers: {'Content-Type': 'application/json', 'X-DNSProbe-Token': token},
    body: JSON.stringify(body)
  };
  const response = await fetch('/api/' + path, options);
  if (!response.ok) throw Error(await response.text());
  return response.json();
}

function selected(id) {
  return [...$(id).querySelectorAll('input:checked')].map(input => input.value);
}

function filterServers() {
  const query = $('serverSearch').value.toLowerCase().trim();
  for (const row of $('servers').children) {
    row.hidden = !row.textContent.toLowerCase().includes(query)
      || (selectedOnly && !row.querySelector('input').checked);
  }
  $('selectVisible').disabled = ![...$('servers').children].some(row =>
    !row.hidden && !row.querySelector('input').disabled);
}

function updateSelection() {
  const checked = selected('servers').map(i => endpoints[+i]);
  const profiles = new Set(checked.map(ep => ep.profile || ep.name)).size;
  const totalRecords = endpoints.filter(ep => !ep.disabled).length;
  $('serversTab').textContent = 'Серверы (' + checked.length + ')';
  $('catalogAll').textContent = 'Все (' + totalRecords + ')';
  $('catalogSelected').textContent = 'Выбранные (' + checked.length + ')';
  $('selectionCount').textContent = 'Выбрано профилей: ' + profiles +
    ' · адресных записей: ' + checked.length + ' из ' + totalRecords;
  filterServers();
  updateParameterSummary();
}

function serverDetails(ep) {
  const details = node('details', undefined, 'server-meta');
  const status = catalogLabels[ep.verification] || 'Пользовательский сервер';
  const summary = node('summary', ep.verification === 'documented' ? '⛨' : 'ⓘ');
  const date = ep.checked && new Date(ep.checked + 'T00:00:00').toLocaleDateString('ru-RU');
  const description = ep.verification === 'documented'
    ? 'Профиль сверен с официальным источником' + (date ? ' (' + date + ')' : '')
    : status + (date ? ' (' + date + ')' : '');
  summary.title = description;
  summary.setAttribute('aria-label', status + ' — сведения о ' + ep.name);
  details.append(summary);
  if (ep.note) details.append(node('p', ep.note, 'hint'));
  const addresses = [
    ep.ip && 'IP: ' + ep.ip, ep.host && 'DoT: ' + ep.host,
    ep.url && 'HTTPS: ' + ep.url, ep.quic && 'DoQ: ' + ep.quic,
    ep.by_name && 'Адрес определяется системным DNS, сертификат проверяется',
    ep.doh_ip && 'DoH bootstrap: ' + ep.doh_ip,
    ep.dot_ip && 'DoT bootstrap: ' + ep.dot_ip,
    ep.doq_ip && 'DoQ bootstrap: ' + ep.doq_ip
  ].filter(Boolean);
  details.append(node('pre', addresses.join('\n')));
  for (const source of ep.sources || []) {
    const link = node('a', 'Источник ↗');
    link.href = source;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    details.append(link);
  }
  return details;
}

function servers(keep) {
  const box = $('servers');
  box.replaceChildren();
  const ordered = endpoints.map((ep, i) => ({ep, i})).sort((a, b) =>
    a.ep.name.localeCompare(b.ep.name, 'ru', {sensitivity: 'base', numeric: true}));
  for (const {ep, i} of ordered) {
    const row = node('div', undefined, 'server-entry');
    const heading = node('div', undefined, 'server-heading');
    const label = node('label', undefined, 'check');
    const input = node('input');
    input.type = 'checkbox';
    input.value = i;
    input.checked = keep ? keep.has(ep.name) : !!ep.default;
    input.disabled = !!ep.disabled;
    input.onchange = updateSelection;
    label.append(input, document.createTextNode(ep.name));
    heading.append(label);
    row.append(serverDetails(ep), heading, node('small',
      (ep.transports || ['udp', 'tcp', 'dot', 'doh']).map(t => t.toUpperCase()).join(' · ')
      + ' | ' + (ep.ip || 'по имени')));
    box.append(row);
  }
  updateSelection();
}

function selectCatalog(only) {
  selectedOnly = only;
  $('catalogAll').setAttribute('aria-pressed', !only);
  $('catalogSelected').setAttribute('aria-pressed', only);
  filterServers();
}

function config() {
  return {
    domains: $('domains').value.split(/[\s,]+/).filter(Boolean),
    endpoints: selected('servers').map(i => endpoints[+i]),
    transports: selected('transports'), types: selected('types'),
    rounds: +$('rounds').value, interval: +$('interval').value, dnssec: $('dnssec').checked
  };
}

function showPanel(historyPanel) {
  $('historyPanel').hidden = !historyPanel;
  $('logPanel').hidden = historyPanel;
  $('historyTab').setAttribute('aria-pressed', historyPanel);
  $('logTab').setAttribute('aria-pressed', !historyPanel);
}

function setPath(key) {
  pathFilter = key;
  showPanel(false);
  for (const row of $('summary').rows) {
    const active = row.dataset.path === pathFilter;
    row.classList.toggle('active', active);
    row.querySelector('button').setAttribute('aria-pressed', active);
  }
  $('results').scrollTop = 0;
  renderLog();
  if (matchMedia('(max-width: 1279px)').matches) {
    $('logTab').scrollIntoView({block: 'nearest'});
  }
}

function renderTable(groups, hasBenchmark) {
  const max = groups.reduce((value, group) =>
    Number.isFinite(group.latency.value) ? Math.max(value, group.latency.value) : value, 0);
  if (pathFilter && !groups.some(group => group.key === pathFilter)) pathFilter = '';
  $('summaryEmpty').hidden = !!(groups.length || hasBenchmark);
  $('summaryTable').hidden = $('tableHint').hidden = !groups.length;
  const metrics = new Set(groups.filter(group => group.latency.count).map(group => group.latency.label));
  const mixed = metrics.size > 1;
  $('tableLatencyTitle').textContent = 'Задержка' + (metrics.size ? ' (' + [...metrics].sort().join(' / ') + ')' : '');
  const coverage = new Map();
  for (const group of groups) {
    const protocol = group.key.split(' / ').at(-1);
    if (!coverage.has(protocol)) coverage.set(protocol, {total: 0, local: 0});
    const counts = coverage.get(protocol);
    counts.total++;
    if (group.local) counts.local++;
  }
  const table = $('summary');
  const focusedPath = table.contains(document.activeElement) ? document.activeElement.closest('tr')?.dataset.path : null;
  table.replaceChildren();

  for (const group of groups) {
    const row = node('tr');
    row.dataset.path = group.key;
    row.classList.toggle('active', pathFilter === group.key);
    row.onclick = () => setPath(pathFilter === group.key ? '' : group.key);

    const name = node('td');
    const button = node('button', group.key, 'path-button');
    button.setAttribute('aria-pressed', pathFilter === group.key);
    const protocol = group.key.split(' / ').at(-1);
    if (termHelp[protocol]) button.title = termHelp[protocol];
    name.append(button);

    const severity = group.errors / group.count > .5 ? 'issue-critical' : group.errors > 0 ? 'issue-warn' : 'issue-clean';
    const issues = node('td', group.errors + ' / ' + group.suspicious +
      ' (' + (100 * group.badRate).toFixed(1) + '%)', severity);
    if (group.local) {
      const counts = coverage.get(protocol);
      const widespread = counts.local * 2 > counts.total;
      const badge = node('span', widespread ? 'IP' : 'Служебный IP ×' + group.local,
        'local-chip' + (widespread ? ' local-chip-compact' : ''));
      const addresses = group.localAddresses;
      const sample = addresses.slice(0, 3).join(', ') + (addresses.length > 3 ? ' и ещё ' + (addresses.length - 3) : '');
      const description = 'Служебный IP' + (sample ? ' (' + sample + ')' : '') + ': ' + group.local + ' из ' + group.count
        + ' измерений. Возможны Fake-IP, VPN или локальная фильтрация.';
      badge.title = description;
      badge.setAttribute('aria-label', description);
      if (widespread) name.append(badge);
      else issues.append(badge);
    }
    const latency = node('td', undefined, 'latency-cell');
    const metric = group.latency;
    if (metric.count) {
      const bar = node('progress', undefined, 'latency-bar');
      bar.max = max || 1;
      bar.value = metric.value;
      bar.setAttribute('aria-hidden', 'true');
      latency.title = metric.count < 20 ? 'Медиана: меньше 20 подходящих ответов' : '95-й перцентиль';
      latency.append(bar, node('span', metric.value.toFixed(1) + ' мс' + (mixed && metric.label === 'p95' ? ' · p95' : ''), 'latency-label'));
    } else {
      latency.textContent = '—';
    }
    row.append(name, node('td', group.received + ' / ' + group.count), issues,
      latency, node('td', String(group.longest)));
    table.append(row);
    if (group.key === focusedPath) button.focus({preventScroll: true});
  }
}

function resultCard(result) {
  const box = node('div', undefined, 'result');
  const status = resultStatus(result);
  box.dataset.result = JSON.stringify([result.at, result.server, result.transport, result.round, result.domain, result.type]);
  const title = node('div', undefined, 'result-title');
  title.append(
    node('span', result.domain + ' · ' + result.type + ' · ' + pathKey(result)),
    node('span', labels[status], 'badge ' + (status === 'received' ? 'passed' : status))
  );
  const tags = node('div', undefined, 'tags');
  const rcode = node('span', result.rcode || 'нет ответа');
  if (termHelp[result.rcode]) rcode.title = termHelp[result.rcode];
  const dnssecNotes = (result.notes || []).filter(note =>
    note.startsWith('DNSSEC: ') || note.startsWith('Отрицательные ответы NSEC/NSEC3'));
  const [label, description, tone] = dnssecLabels[result.dnssec] || dnssecLabels.indeterminate;
  const dnssec = node('span', 'DNSSEC: ' + label, 'dnssec-tag ' + tone);
  dnssec.title = [description, ...dnssecNotes].join(' ');
  const ad = node('span', 'AD: ' + result.ad);
  ad.title = termHelp.AD;
  tags.append(node('span', result.ms.toFixed(1) + ' мс'), rcode);
  if (result.dnssec && result.dnssec !== 'not_checked') tags.append(dnssec);
  const details = node('details', undefined, 'result-details');
  const metadata = node('div', undefined, 'tags');
  metadata.append(node('span', new Date(result.at).toLocaleTimeString('ru-RU')),
    node('span', 'цикл ' + result.round), ad);
  if (result.route) metadata.append(node('span', result.route));
  if (result.fallback) metadata.append(node('span', 'UDP → TCP'));
  details.append(node('summary', 'Детали'), metadata);
  box.append(title, tags, details);
  for (const answer of result.answers || []) {
    const fields = answer.trim().split(/\s+/);
    if (fields.length < 5) {
      details.append(node('pre', answer));
      continue;
    }
    const line = node('div', undefined, 'response-table');
    const [domain, ttl, cls, type, ...data] = fields;
    line.append(...[domain, ttl, cls, type, data.join(' ')].map(value => node('span', value)));
    details.append(line);
  }
  if (result.error) details.append(node('p', result.error, 'result-note error'));
  for (const note of result.notes || []) {
    if (!dnssecNotes.includes(note)) details.append(node('p', note, 'result-note'));
  }
  return box;
}

function pathKey(result) {
  return result.server + ' / ' + result.transport.toUpperCase();
}

function renderLog() {
  const query = $('logSearch').value.trim().toLowerCase();
  const all = run?.results || [];
  const filtered = all.filter(result => {
    if (pathFilter && pathKey(result) !== pathFilter) return false;
    if (query && ![result.domain, ...(result.ips || [])].some(value =>
      value.toLowerCase().includes(query))) return false;
    if (statusFilter === 'all') return true;
    const status = resultStatus(result);
    if (statusFilter === 'passed') return ['passed', 'received'].includes(status);
    if (statusFilter === 'issues') return ['suspicious', 'error'].includes(status);
    return statusFilter === status || (statusFilter === 'insufficient' && status === 'local');
  }).slice(-200).reverse();

  $('logTab').textContent = 'Журнал измерений (' + filtered.length + ')';
  $('pathFilter').hidden = !pathFilter;
  $('pathName').textContent = pathFilter ? 'Путь: ' + pathFilter : '';
  const box = $('results');
  const offset = box.scrollTop;
  const opened = new Set([...box.querySelectorAll('details[open]')].map(el => el.closest('.result').dataset.result));
  box.replaceChildren(...filtered.map(result => {
    const card = resultCard(result);
    card.querySelector('details').open = opened.has(card.dataset.result);
    return card;
  }));
  if (!filtered.length) box.append(node('div', all.length ? 'Нет записей по фильтрам' : 'Нет измерений', 'empty'));
  box.scrollTop = offset;
}

const russianPlural = new Intl.PluralRules('ru-RU');

function issueLabel(count, forms) {
  return count + ' ' + forms[russianPlural.select(count)];
}

function updateIssueKpi(errors, suspicious) {
  const errorLabel = issueLabel(errors, {one: 'ошибка', few: 'ошибки', many: 'ошибок'});
  $('issues').textContent = errors + ' / ' + (suspicious ?? '—');
  $('issuesCount').textContent = suspicious == null ? errorLabel
    : errorLabel + ' · ' + issueLabel(suspicious, {one: 'подозрительный', few: 'подозрительных', many: 'подозрительных'});
}

function openPathInJournal(key, domain = '') {
  $('logSearch').value = domain;
  setLogStatus('all');
  setPath(key);
  $('logTab').focus({preventScroll: true});
}

function latencyRange(groups, encrypted) {
  const values = groups.filter(group => {
    const protocol = group.key.split(' / ').at(-1);
    return encrypted === ['DOT', 'DOH', 'DOH3', 'DOQ'].includes(protocol);
  }).map(group => group.latency.median).filter(Number.isFinite);
  if (!values.length) return '';
  const min = Math.round(Math.min(...values));
  const max = Math.round(Math.max(...values));
  return (min === max ? min : min + '–' + max) + ' мс';
}

const protocolNames = {udp:'UDP', tcp:'TCP', dot:'DoT', doh:'DoH', doh3:'DoH3', doq:'DoQ'};

function describeFailures(groups, config, state) {
  const profiles = new Map((config?.endpoints || []).map(endpoint => [endpoint.name, endpoint.profile || endpoint.name]));
  const affected = new Map();
  for (const group of groups.filter(group => group.badRate)) {
    const profile = profiles.get(group.server) || group.server.replace(/ · резервный$/, '');
    const protocol = protocolNames[group.transport] || group.transport.toUpperCase();
    const key = profile + ' / ' + protocol;
    if (!affected.has(key)) affected.set(key, {profile, protocol, groups: [], healthy: 0});
    affected.get(key).groups.push(group);
  }
  for (const group of groups.filter(group => !group.badRate)) {
    const profile = profiles.get(group.server) || group.server.replace(/ · резервный$/, '');
    const protocol = protocolNames[group.transport] || group.transport.toUpperCase();
    const cluster = affected.get(profile + ' / ' + protocol);
    if (cluster) cluster.healthy++;
  }
  const summaries = [...affected.values()].map(({profile, protocol, groups, healthy}) => {
    const total = groups.reduce((sum, group) => sum + group.count, 0);
    const timeouts = groups.reduce((sum, group) => sum + group.timeouts, 0);
    const errors = groups.reduce((sum, group) => sum + group.errors, 0);
    const suspicious = groups.reduce((sum, group) => sum + group.suspicious, 0);
    const addresses = groups.length > 1 ? ' (' + issueLabel(groups.length,
      {one:'адрес', few:'адреса', many:'адресов'}) + ')' : '';
    if (timeouts === total) {
      const unavailable = state === 'done' && !healthy;
      const label = unavailable ? profile + ' недоступен по ' + protocol : profile + ' / ' + protocol;
      return label + addresses + ' · ' + timeouts + '/' + total + ' таймаутов';
    }
    const parts = [];
    if (timeouts) parts.push(issueLabel(timeouts, {one:'таймаут', few:'таймаута', many:'таймаутов'}));
    if (errors > timeouts) parts.push(issueLabel(errors - timeouts, {one:'ошибка', few:'ошибки', many:'ошибок'}));
    if (suspicious) parts.push(issueLabel(suspicious, {one:'расхождение', few:'расхождения', many:'расхождений'}));
    return profile + ' / ' + protocol + addresses + ' — ' + parts.join(', ') + ' из ' + total;
  });
  if (summaries.length > 2) return summaries.slice(0, 2).join('. ') + '. Ещё групп с проблемами: ' + (summaries.length - 2) + '.';
  return summaries.join('. ') + '.';
}

function renderVerdict(groups, state, rows, config) {
  $('verdict').hidden = !groups.length;
  if (!groups.length) return;
  const [worst] = groups;
  const failedPaths = groups.filter(group => group.badRate).length;
  const prefix = state === 'running' ? 'Пока: ' : state === 'stopped' ? 'До остановки: ' : '';
  const action = $('showProblem');
  let message, tone;
  if (worst.badRate) {
    tone = worst.errors / worst.count > .5 ? 'critical' : worst.errors ? 'warn' : 'info';
    message = describeFailures(groups, config, state);
    if (state === 'done' && failedPaths < groups.length) {
      message += ' Остальные измеренные пути — без сбоев и расхождений.';
    }
  } else {
    tone = 'good';
    message = 'Ответы получены по всем измеренным путям (' + groups.length + '). Сбоев и расхождений не обнаружено.';
    const plain = latencyRange(groups, false);
    const encrypted = latencyRange(groups, true);
    if (plain && encrypted) message += ' Медианы по путям: обычный DNS — ' + plain + ', шифрованный — ' + encrypted + '.';
  }
  $('verdictMain').className = 'verdict verdict-' + tone;
  action.hidden = !worst.badRate;
  action.title = worst.key;
  action.onclick = () => openPathInJournal(worst.key);
  if ($('verdictText').textContent !== prefix + message) $('verdictText').textContent = prefix + message;

  const local = rows.filter(isLocalAddress);
  $('localVerdict').hidden = !local.length;
  if (!local.length) return;
  const sample = local.find(row => (row.ips || []).some(ip => /^198\.(18|19)\./.test(ip))) || local[0];
  const address = sample.notes.find(note => note.startsWith('Служебный/непубличный адрес:'))
    ?.split(': ').at(1)?.split(';')[0];
  const sameLookup = local.filter(row => row.domain === sample.domain && (row.notes || []).some(note =>
    note.startsWith('Служебный/непубличный адрес: ' + address + ';') ||
    note === 'Служебный/непубличный адрес: ' + address));
  const protocols = [...new Set((sameLookup.length ? sameLookup : [sample]).map(row => row.transport.toUpperCase()))].join('/');
  const count = groups.filter(group => group.local).length;
  $('localVerdictText').textContent = 'Служебный IP' + (address ? ' ' + address : '') + ' для '
    + sample.domain + ' по ' + protocols + '. Возможен Fake-IP / VPN. Путей со служебными IP: ' + count + '.';
  $('showLocal').onclick = () => openPathInJournal(pathKey(sample), sample.domain);
}

function runProgress(r) {
  if (!r?.total || r.state === 'benchmark' || r.benchmark) return '';
  const completed = Math.min(r.total, r.progress);
  let text = Math.floor(100 * completed / r.total) + '% (' + completed + ' / ' + r.total + ')';
  if (r.state === 'running' && completed >= 3 && completed < r.total && !viewingHistory) {
    const elapsed = (Date.now() - new Date(r.started).getTime()) / 1000;
    const left = Math.max(1, Math.ceil(elapsed * (r.total - completed) / completed));
    if (Number.isFinite(left)) text += left >= 60 ? ' · ≈ ' + Math.ceil(left / 60) + ' мин' : ' · ≈ ' + left + ' сек';
  }
  return text;
}

function durationLabel(seconds) {
  const rounded = Math.max(0, Math.round(seconds));
  const hours = Math.floor(rounded / 3600);
  const minutes = Math.floor(rounded / 60) % 60;
  const rest = rounded % 60;
  return [hours ? hours + ' ч' : '', minutes ? minutes + ' мин' : '', rest || rounded < 60 ? rest + ' сек' : '']
    .filter(Boolean).join(' ');
}

function finishedSummary(run, groups) {
  if (run?.state !== 'done' || !run.finished) return '';
  const seconds = (new Date(run.finished).getTime() - new Date(run.started).getTime()) / 1000;
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  const servers = new Map();
  for (const group of groups) servers.set(group.server, (servers.get(group.server) || 0) + group.errors);
  const clean = [...servers.values()].filter(count => count === 0).length;
  return 'Завершено за ' + durationLabel(seconds)
    + (servers.size ? ' · ' + clean + ' из ' + servers.size + ' серверов без ошибок' : '');
}

function render(r) {
  if (run?.id !== r?.id) {
    pathFilter = '';
    $('results').scrollTop = 0;
  }
  run = r;
  const rows = r?.results || [];
  const active = ['running', 'benchmark'].includes(liveRun?.state);
  $('state').textContent = ({
    running: 'Идёт диагностика', benchmark: 'Идёт нагрузочный тест',
    done: 'Проверка завершена', stopped: 'Остановлено'
  })[liveRun?.state] || 'Готов к проверке';
  $('start').hidden = active;
  $('start').disabled = $('benchmark').disabled = active;
  $('stop').hidden = !active;
  $('export').disabled = !r;
  $('live').hidden = !viewingHistory;
  $('progress').textContent = r
    ? new Date(r.started).toLocaleString('ru-RU') + (viewingHistory ? ' · Архив' : '')
    : 'Запустите проверку, чтобы увидеть измерения.';
  $('progressCount').textContent = runProgress(r);
  $('bar').max = r?.total || 1;
  $('bar').value = r?.progress || 0;

  const received = rows.filter(x => !x.error);
  $('availability').textContent = rows.length ? (100 * received.length / rows.length).toFixed(1) + '%' : '—';
  $('packetCount').textContent = rows.length
    ? received.length + ' / ' + rows.length + ' пакетов (включая NXDOMAIN и SERVFAIL)' : '—';
  if (rows.length) {
    updateIssueKpi(rows.filter(x => resultStatus(x) === 'error').length,
      rows.filter(x => resultStatus(x) === 'suspicious').length);
  } else {
    $('issues').textContent = $('issuesCount').textContent = '—';
  }
  const metric = latencyMetric(rows);
  $('latency').textContent = metric.count ? metric.value.toFixed(1) + ' мс' : '—';
  $('latencyTitle').textContent = metric.count ? 'Задержка ' + metric.label : 'Задержка';
  $('latencyHint').textContent = metric.count ? (metric.count < 20 ? 'Медиана · ' : 'p95 · ') + issueLabel(metric.count, {one:'замер', few:'замера', many:'замеров'}) : '—';
  if (metric.count && metric.count < 20) $('latencyHint').textContent += ' · предварительно';
  if (r?.error) $('error').textContent = r.error;

  const groups = rankResults(rows);
  const finished = finishedSummary(r, groups);
  if (finished) $('progress').textContent = finished + (viewingHistory ? ' · Архив' : '');
  $('progress').title = r?.started ? new Date(r.started).toLocaleString('ru-RU') : '';
  if (!viewingHistory) $('state').title = finished;
  renderVerdict(groups, r?.state, rows, r?.config);
  renderTable(groups, !!r?.benchmark);
  renderLog();
  $('benchmarkResult').hidden = !r?.benchmark;
  if (r?.benchmark) {
    const b = r.benchmark;
    const packets = b.totalRequests - b.totalIOErrors;
    $('benchmarkResult').textContent = JSON.stringify(b, null, 2);
    $('availability').textContent = b.totalRequests ? (100 * packets / b.totalRequests).toFixed(1) + '%' : '—';
    $('packetCount').textContent = packets + ' / ' + b.totalRequests + ' пакетов';
    updateIssueKpi(b.totalIOErrors + b.totalErrorResponses, null);
    const label = packets >= 20 ? 'p95' : 'p50';
    const latency = b.latencyStats?.[label + 'Ms'];
    $('latencyTitle').textContent = 'Задержка ' + label;
    $('latency').textContent = packets > 0 && latency != null ? latency + ' мс' : '—';
    $('latencyHint').textContent = packets > 0 ? packets + ' ответов' + (packets < 20 ? ' · предварительно' : '') : '—';
    $('progress').textContent = 'dnspyre · ' + b.totalRequests + ' запросов · '
      + b.benchmarkDurationSeconds + ' с · ' + b.queriesPerSecond + ' QPS. Корректность ответов в этом режиме не проверяется.';
  }
}

async function history() {
  const entries = await api('history');
  $('history').replaceChildren();
  if (!entries.length) $('history').append(node('div', 'Нет сохранённых проверок', 'empty'));
  for (const entry of entries.slice(0, 100)) {
    const title = new Date(entry.started).toLocaleString('ru-RU', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    const button = node('button', title, 'secondary');
    button.onclick = () => guard(async () => {
      const version = ++requestVersion;
      const saved = await api('history/' + entry.id);
      if (version !== requestVersion) return;
      viewingHistory = true;
      render(saved);
      showPanel(false);
    });
    $('history').append(button);
  }
}

async function guard(action, clear = true) {
  try {
    if (clear) $('error').textContent = '';
    await action();
  } catch (error) {
    $('error').textContent = error.message;
  }
}

async function start(path, body) {
  const version = ++requestVersion;
  const next = await api(path, body);
  if (version !== requestVersion) return;
  liveRun = next;
  viewingHistory = false;
  render(next);
  showPanel(false);
}

function showSettings(serversVisible) {
  $('serversPanel').hidden = !serversVisible;
  $('paramsPanel').hidden = serversVisible;
  $('serversTab').setAttribute('aria-pressed', serversVisible);
  $('paramsTab').setAttribute('aria-pressed', !serversVisible);
}

function updateParameterSummary() {
  const {domains, endpoints, transports, types, rounds, interval, dnssec} = config();
  const parts = [
    issueLabel(domains.length, {one:'домен', few:'домена', many:'доменов'}),
    issueLabel(transports.length, {one:'протокол', few:'протокола', many:'протоколов'}),
    issueLabel(rounds || 0, {one:'цикл', few:'цикла', many:'циклов', other:'цикла'})
  ];
  const baseline = {udp:.08, tcp:.12, dot:.25, doh:.25, doh3:.30, doq:.25};
  let paths = 0, secondsPerQuestion = 0;
  for (const endpoint of endpoints) {
    for (const protocol of transports) {
      if (endpoint.disabled || (endpoint.transports?.length && !endpoint.transports.includes(protocol))) continue;
      paths++;
      secondsPerQuestion += baseline[protocol] + .10 + (dnssec ? .45 : 0);
    }
  }
  const attempts = paths * domains.length * types.length * rounds;
  const summary = $('parameterSummary');
  summary.title = 'Открыть параметры проверки';
  if (Number.isInteger(attempts) && attempts > 0 && attempts <= 100000 && rounds <= 1440 && interval >= 1 && interval <= 3600) {
    const seconds = secondsPerQuestion * domains.length * types.length * rounds + interval * (rounds - 1);
    const step = seconds >= 120 ? 60 : seconds >= 20 ? 5 : 1;
    parts.push('≈ ' + durationLabel(Math.ceil(seconds / step) * step));
    summary.title += ' · ' + attempts + ' замеров. Оценка учитывает поддерживаемые протоколы, паузы'
      + (dnssec ? ' и условное время DNSSEC' : '') + '. Таймауты и сеть могут увеличить время.';
  }
  summary.textContent = parts.join(' · ');
}

for (const id of ['domains','transports','types','rounds','interval','dnssec']) $(id).addEventListener('input', updateParameterSummary);
$('parameterSummary').onclick = () => {
  showSettings(false);
  $('paramsTab').focus();
};
updateParameterSummary();

$('serversTab').onclick = () => showSettings(true);
$('paramsTab').onclick = () => showSettings(false);
$('openCustom').onclick = () => {
  $('customError').textContent = '';
  $('customServer').showModal();
};
$('closeCustom').onclick = () => $('customServer').close();

$('catalogAll').onclick = () => selectCatalog(false);
$('catalogSelected').onclick = () => selectCatalog(true);
$('serverSearch').oninput = filterServers;
$('clearServers').onclick = () => {
  for (const input of $('servers').querySelectorAll('input')) input.checked = false;
  updateSelection();
};
$('selectVisible').onclick = () => {
  for (const row of $('servers').children) {
    const input = row.querySelector('input');
    if (!row.hidden && !input.disabled) input.checked = true;
  }
  updateSelection();
};
$('logTab').onclick = () => showPanel(false);
$('historyTab').onclick = () => showPanel(true);
$('logSearch').oninput = () => { $('results').scrollTop = 0; renderLog(); };
$('resetPath').onclick = () => {
  const button = [...$('summary').rows].find(row => row.dataset.path === pathFilter)?.querySelector('button');
  setPath('');
  button?.focus({preventScroll: true});
};
function setLogStatus(status) {
  statusFilter = status;
  for (const item of $('logStatuses').querySelectorAll('button')) {
    item.setAttribute('aria-pressed', item.dataset.status === status);
  }
  $('results').scrollTop = 0;
  renderLog();
}
for (const button of $('logStatuses').querySelectorAll('button')) {
  button.onclick = () => setLogStatus(button.dataset.status);
}
$('live').onclick = () => {
  requestVersion++;
  viewingHistory = false;
  render(liveRun);
  showPanel(false);
};
$('start').onclick = () => guard(() => start('start', config()));
$('stop').onclick = () => guard(async () => { await api('stop', {}); });
$('benchmark').onclick = () => guard(() =>
  start('benchmark', {config: config(), qps: +$('qps').value, seconds: +$('seconds').value}));
$('refresh').onclick = () => guard(history);
$('add').onclick = () => {
  $('customError').textContent = '';
  const ep = {
    name: $('customName').value.trim(), ip: $('customIP').value.trim(),
    host: $('customHost').value.trim(), url: $('customURL').value.trim(),
    quic: $('customQUIC').value.trim(), transports: []
  };
  if (!ep.name) { $('customError').textContent = 'Укажите название'; return; }
  if (endpoints.some(x => x.name === ep.name)) { $('customError').textContent = 'Такое название уже есть'; return; }
  if (ep.ip) ep.transports.push('udp', 'tcp');
  if (ep.host) ep.transports.push('dot');
  if (ep.url) {
    ep.transports.push('doh');
    if ($('customH3').checked) ep.transports.push('doh3');
  }
  if (ep.quic) ep.transports.push('doq');
  if (!ep.transports.length) { $('customError').textContent = 'Укажите адрес сервера'; return; }
  const keep = new Set(selected('servers').map(i => endpoints[+i].name));
  keep.add(ep.name);
  endpoints.push(ep);
  servers(keep);
  $('customServer').close();
};
$('export').onclick = () => {
  if (!run) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(run, null, 2)], {type: 'application/json'}));
  const link = node('a');
  link.href = url;
  link.download = 'dnsprobe-' + run.id + '.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

async function refreshCurrent() {
  const version = requestVersion;
  const next = await api('current');
  if (version !== requestVersion) return;
  const changed = next?.id !== liveRun?.id || next?.state !== liveRun?.state;
  const advanced = next?.progress !== liveRun?.progress || next?.completed_rounds !== liveRun?.completed_rounds;
  liveRun = next;
  if (viewingHistory) {
    const active = ['running', 'benchmark'].includes(liveRun?.state);
    $('start').disabled = $('benchmark').disabled = active;
    $('stop').hidden = !active;
  } else if (changed || advanced || run !== null && !next) {
    render(next);
  }
  if (changed) await history();
}

guard(async () => {
  const meta = await api('meta');
  token = meta.token;
  endpoints = meta.endpoints;
  servers();
  liveRun = await api('current');
  render(liveRun);
  await history();
  setInterval(() => guard(refreshCurrent, false), 2000);
});
