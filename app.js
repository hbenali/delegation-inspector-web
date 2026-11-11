/* Delegation Checker: client-side inspection of a domain's DNS delegation (NS, nameserver addresses, SOA,
   DNSSEC) over DNS-over-HTTPS (dns.google, cross-checked with cloudflare-dns.com).
   No dependencies, no inline code (CSP: script-src 'self').
   A browser cannot query authoritative servers (no raw UDP/TCP), so lame delegation, parent-versus-child NS
   and per-server SOA serials are NOT checked here; the UI says so. */
(function () {
  'use strict';

  var GOOGLE = 'https://dns.google/resolve';
  var CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';
  var MAX_NS = 12; // bound the number of nameservers resolved
  var $ = function (id) { return document.getElementById(id); };

  // ---- Providers (detection by NS hostname suffix) ----
  var PROVIDERS = [
    { name: 'Cloudflare', match: /\.ns\.cloudflare\.com$/ },
    { name: 'Amazon Route 53', match: /\.awsdns-\d+\.(com|net|org|co\.uk)$/ },
    { name: 'Google Cloud DNS / Google Domains', match: /\.googledomains\.com$/ },
    { name: 'Microsoft Azure DNS', match: /\.azure-dns\.(com|net|org|info)$/ },
    { name: 'OVHcloud', match: /\.(ovh\.net|ovh\.com|anycast\.me)$/ },
    { name: 'Gandi', match: /\.gandi\.net$/ },
    { name: 'NS1', match: /\.nsone\.net$/ },
    { name: 'DigitalOcean', match: /\.digitalocean\.com$/ },
    { name: 'Hetzner', match: /\.(your-server\.de|hetzner\.(com|de))$/ },
    { name: 'GoDaddy', match: /\.domaincontrol\.com$/ },
    { name: 'Namecheap', match: /\.(registrar-servers\.com|namecheaphosting\.com)$/ },
    { name: 'IONOS', match: /\.(ui-dns\.(com|de|org|biz)|ionos\.(com|de))$/ },
    { name: 'Vercel DNS', match: /\.vercel-dns\.com$/ },
    { name: 'Akamai (Edge DNS)', match: /\.akam(ai)?\.net$|\.akamaiedge\.net$/ },
    { name: 'Dyn / Oracle', match: /\.dynect\.net$/ },
    { name: 'UltraDNS / Vercara', match: /\.ultradns\.(com|net|org|biz|info)$/ },
    { name: 'DNSimple', match: /\.dnsimple\.com$/ },
    { name: 'Linode / Akamai Cloud', match: /\.linode\.com$/ },
    { name: 'Hurricane Electric', match: /\.he\.net$/ },
    { name: 'Scaleway', match: /\.scaleway\.com$/ },
    { name: 'Infomaniak', match: /\.infomaniak\.ch$/ },
    { name: 'Bunny DNS', match: /\.bunny\.net$/ },
    { name: 'deSEC', match: /\.desec\.(io|org)$/ },
    { name: 'Porkbun', match: /\.porkbun\.com$/ },
    { name: 'Wix', match: /\.wixdns\.net$/ },
    { name: 'Hostinger', match: /\.dns-parking\.com$/ },
    { name: 'DNS Made Easy', match: /\.dnsmadeeasy\.com$/ },
    { name: 'Rackspace', match: /\.rackspace\.com$/ }
  ];
  function detectProvider(host) {
    for (var i = 0; i < PROVIDERS.length; i++) if (PROVIDERS[i].match.test(host)) return PROVIDERS[i].name;
    return null;
  }

  // ---- DNS helpers ----
  function normalizeDomain(input) {
    return String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/\.+$/, '');
  }
  function validDomain(d) {
    if (!d || d.length > 253) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(l) || /^xn--[a-z0-9-]+$/i.test(l); });
  }
  function stripDot(s) { return String(s).replace(/\.$/, '').toLowerCase(); }
  function isIPv4(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h); }

  // One DoH query. Request URLs are only ever built from hostnames that passed validDomain().
  async function doh(base, name, type, cd) {
    name = stripDot(name);
    if (!validDomain(name)) throw new Error('invalid name');
    var url = base + '?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type) + (cd ? '&cd=1' : '');
    var res = await fetch(url, { headers: { Accept: 'application/dns-json' } });
    if (!res.ok) throw new Error('DNS query failed (HTTP ' + res.status + ')');
    return res.json();
  }
  function answers(d, type) { return ((d && d.Answer) || []).filter(function (x) { return x.type === type; }); }

  function isPrivateV4(ip) {
    var p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  function isPrivateV6(ip) { return /^(::1?|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)/i.test(ip); }

  // /24 key for IPv4, /48 key for IPv6.
  function net4(ip) { return ip.split('.').slice(0, 3).join('.') + '.0/24'; }
  function net6(ip) {
    var parts = ip.toLowerCase().split('::');
    var head = parts[0] ? parts[0].split(':') : [], tail = parts[1] ? parts[1].split(':') : [];
    var fill = parts.length > 1 ? new Array(Math.max(0, 8 - head.length - tail.length)).fill('0') : [];
    var g = head.concat(fill, tail).map(function (x) { return x.replace(/^0+(?=.)/, ''); });
    return g.slice(0, 3).join(':') + '::/48';
  }

  async function resolveHost(host) {
    var out = { host: host, a: [], aaaa: [], cname: null, error: null };
    if (isIPv4(host) || host.indexOf(':') !== -1) { out.literal = true; return out; }
    if (!validDomain(host)) { out.error = 'not a valid hostname'; return out; }
    try {
      var r = await Promise.all([doh(GOOGLE, host, 'A'), doh(GOOGLE, host, 'AAAA')]);
      var all = (r[0].Answer || []).concat(r[1].Answer || []);
      var cn = all.filter(function (x) { return x.type === 5; })[0];
      if (cn) out.cname = stripDot(cn.data);
      out.a = answers(r[0], 1).map(function (x) { return x.data; });
      out.aaaa = answers(r[1], 28).map(function (x) { return x.data; });
      if (r[0].Status === 3 && r[1].Status === 3) out.error = 'NXDOMAIN';
      else if (r[0].Status === 2 && r[1].Status === 2) out.error = 'SERVFAIL';
    } catch (e) { out.error = e.message; }
    return out;
  }

  // ---- Parsers ----
  function parseSOA(data) {
    var p = String(data).trim().split(/\s+/);
    if (p.length < 7) return null;
    var n = p.slice(2, 7).map(Number);
    if (n.some(function (x) { return !isFinite(x); })) return null;
    return { mname: stripDot(p[0]) || '.', rname: p[1], serial: n[0], refresh: n[1], retry: n[2], expire: n[3], minimum: n[4] };
  }
  // RNAME "hostmaster.example.com." -> hostmaster@example.com ; "john\.doe.example.com." -> john.doe@example.com
  function decodeRname(r) {
    var s = String(r).replace(/\.$/, ''), i = 0, local = '';
    while (i < s.length) {
      if (s[i] === '\\' && i + 1 < s.length) { local += s[i + 1]; i += 2; continue; }
      if (s[i] === '.') break;
      local += s[i]; i++;
    }
    var domain = s.slice(i + 1);
    return local && domain ? local + '@' + domain : String(r);
  }
  function parseDS(data) {
    var p = String(data).trim().split(/\s+/);
    if (p.length < 4) return null;
    return { tag: parseInt(p[0], 10), alg: parseInt(p[1], 10), dtype: parseInt(p[2], 10) };
  }
  function parseDNSKEY(data) {
    var p = String(data).trim().split(/\s+/);
    if (p.length < 4) return null;
    return { flags: parseInt(p[0], 10), alg: parseInt(p[2], 10) };
  }
  var ALG = { 3: 'DSA', 5: 'RSASHA1', 6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256', 10: 'RSASHA512', 12: 'ECC-GOST', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448' };
  var DIGEST = { 1: 'SHA-1', 2: 'SHA-256', 3: 'GOST R 34.11-94', 4: 'SHA-384' };

  function fmtDur(s) {
    if (s === 0) return '0s';
    var u = [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]], out = [];
    for (var i = 0; i < u.length && out.length < 2; i++) {
      var q = Math.floor(s / u[i][1]);
      if (q > 0) { out.push(q + u[i][0]); s -= q * u[i][1]; }
    }
    return out.join(' ');
  }

  // Serial style: YYYYMMDDnn, Unix timestamp, or plain counter.
  function serialStyle(serial) {
    var s = String(serial);
    if (/^\d{10}$/.test(s)) {
      var y = +s.slice(0, 4), m = +s.slice(4, 6), d = +s.slice(6, 8), nn = s.slice(8);
      var dt = new Date(Date.UTC(y, m - 1, d));
      if (y >= 1990 && y <= 2100 && m >= 1 && m <= 12 && d >= 1 && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d) {
        return { kind: 'date', date: dt, text: y + '-' + s.slice(4, 6) + '-' + s.slice(6, 8), rev: nn };
      }
    }
    if (serial >= 946684800 && serial <= Date.now() / 1000 + 86400 && s.length === 10) {
      var ts = new Date(serial * 1000);
      return { kind: 'unix', date: ts, text: ts.toISOString().slice(0, 19).replace('T', ' ') + ' UTC' };
    }
    return { kind: 'counter' };
  }

  // Timer sanity ranges. RFC 1912 section 2.2 and RIPE-203 recommended values.
  var TIMERS = [
    { key: 'refresh', label: 'Refresh', ripe: 86400, rfc: '1200 to 43200 (20m to 12h)', lo: 1200, hi: 86400 },
    { key: 'retry', label: 'Retry', ripe: 7200, rfc: '180 to 900 (3m to 15m)', lo: 180, hi: 7200 },
    { key: 'expire', label: 'Expire', ripe: 3600000, rfc: '1209600 to 2419200 (2 to 4 weeks)', lo: 1209600, hi: 3600000 },
    { key: 'minimum', label: 'Minimum (negative TTL)', ripe: 172800, rfc: '86400 to 432000 (1 to 5 days, pre-RFC 2308)', lo: 60, hi: 432000 }
  ];
  function timerVerdict(t, v) {
    if (v < t.lo) return t.key === 'minimum' ? { level: 'warn', text: 'very low: queries for missing names are not cached' } : { level: 'info', text: 'below the recommended range (aggressive)' };
    if (v > t.hi) return { level: 'warn', text: 'above the recommended range' };
    if (t.key === 'minimum' && v < 86400) return { level: 'ok', text: 'within RFC 2308 practice (negative caching TTL, hours or less is common)' };
    return { level: 'ok', text: 'within the recommended range' };
  }

  // ---- DNS gathering ----
  async function safe(p) { try { return await p; } catch (e) { return null; } }

  async function queryZone(base, domain) {
    var r = await Promise.all([
      safe(doh(base, domain, 'NS')), safe(doh(base, domain, 'SOA')),
      safe(doh(base, domain, 'DS')), safe(doh(base, domain, 'DNSKEY'))
    ]);
    return { ns: r[0], soa: r[1], ds: r[2], dnskey: r[3] };
  }
  function nsSet(d) { return answers(d, 2).map(function (x) { return stripDot(x.data); }).filter(Boolean); }
  function uniq(a) { return a.filter(function (x, i) { return a.indexOf(x) === i; }); }

  // ---- Checks ----
  function buildChecks(info) {
    var checks = [];
    var add = function (level, text) { checks.push({ level: level, text: text }); };
    var hosts = info.hosts, resolved = info.resolved;

    // Name servers
    var distinct = uniq(hosts);
    if (hosts.length !== distinct.length) add('warn', 'Some nameservers are listed more than once.');
    if (distinct.length >= 2) add('pass', distinct.length + ' nameservers (RFC 2182 asks for at least two).');
    else add('fail', 'Only ' + distinct.length + ' nameserver: RFC 2182 requires at least two, on separate networks.');
    if (distinct.length > 8) add('info', distinct.length + ' nameservers is a lot; the NS answer may no longer fit in a 512-byte UDP response and need TCP or EDNS0.');

    var v4keys = {}, v6keys = {}, anyV6 = false;
    distinct.forEach(function (h) {
      var r = resolved[h];
      if (!r) return;
      if (r.literal) { add('fail', h + ' is an IP address; an NS target must be a hostname.'); return; }
      if (r.error === 'NXDOMAIN') { add('fail', h + ' does not exist (NXDOMAIN): the delegation points to a name that is not in DNS.'); return; }
      if (r.error) { add('warn', h + ': address lookup failed (' + r.error + ').'); return; }
      if (r.cname) add('fail', h + ' is a CNAME to ' + r.cname + '; an NS target must not be an alias (RFC 2181 section 10.3).');
      if (!r.a.length && !r.aaaa.length) { add('fail', h + ' has no A or AAAA record.'); return; }
      if (r.a.some(isPrivateV4) || r.aaaa.some(isPrivateV6)) add('fail', h + ' resolves to a private or loopback address; it is unreachable from the internet.');
      if (r.aaaa.length) anyV6 = true;
      r.a.forEach(function (ip) { (v4keys[net4(ip)] = v4keys[net4(ip)] || []).push(h); });
      r.aaaa.forEach(function (ip) { (v6keys[net6(ip)] = v6keys[net6(ip)] || []).push(h); });
      if (h === info.domain || h.slice(-info.domain.length - 1) === '.' + info.domain) add('info', h + ' is inside the zone it serves, so the parent must publish glue records for it (not checkable from a browser).');
    });
    var exists = distinct.filter(function (h) { var r = resolved[h]; return r && !r.literal && !r.error; });
    if (distinct.length && !checks.some(function (c) { return c.level === 'fail' || (c.level === 'warn' && /lookup failed/.test(c.text)); }) && exists.length === distinct.length) add('pass', 'Every nameserver name exists and resolves to an address; none is a CNAME or an IP literal.');

    // Network diversity
    var k4 = Object.keys(v4keys), k6 = Object.keys(v6keys);
    // Two nameservers count as co-located only if they share a network in every address family both have.
    var sharedPairs = [];
    for (var i = 0; i < distinct.length; i++) for (var j = i + 1; j < distinct.length; j++) {
      var ra = resolved[distinct[i]], rb = resolved[distinct[j]];
      if (!ra || !rb || ra.error || rb.error || ra.literal || rb.literal) continue;
      var inter = function (x, y, f) { return x.map(f).some(function (k) { return y.map(f).indexOf(k) >= 0; }); };
      var fam = [];
      if (ra.a.length && rb.a.length) fam.push(inter(ra.a, rb.a, net4));
      if (ra.aaaa.length && rb.aaaa.length) fam.push(inter(ra.aaaa, rb.aaaa, net6));
      if (fam.length && fam.every(Boolean)) sharedPairs.push(distinct[i] + ' and ' + distinct[j]);
    }
    if (k4.length || k6.length) {
      var diverse4 = k4.length >= 2, diverse6 = k6.length >= 2;
      if (diverse4 || diverse6) add('pass', 'Nameserver addresses span ' + (diverse4 ? k4.length + ' IPv4 /24 networks' : '') + (diverse4 && diverse6 ? ' and ' : '') + (diverse6 ? k6.length + ' IPv6 /48 networks' : '') + '.');
      else if (distinct.length >= 2) add('fail', 'All nameserver addresses are in a single network (' + (k4[0] || k6[0]) + '): RFC 2182 asks for topologically separate servers.');
      sharedPairs.forEach(function (p) { add('warn', p + ' share the same network (IPv4 /24 and IPv6 /48): one network outage would take them down together.'); });
      add('info', 'Network diversity is judged on /24 (IPv4) and /48 (IPv6) only; anycast providers can look co-located here while being globally distributed.');
    }
    if (exists.length) {
      if (anyV6) add('pass', 'At least one nameserver has an IPv6 address.');
      else add('warn', 'No nameserver has an IPv6 (AAAA) address: IPv6-only resolvers cannot reach this zone.');
    }

    // SOA
    var soa = info.soa;
    if (!soa) add('warn', 'No SOA record returned for ' + info.domain + '.');
    else {
      if (distinct.length && distinct.indexOf(soa.mname) < 0) add('info', 'The SOA primary (' + soa.mname + ') is not in the NS set: normal for hidden-primary setups, otherwise worth a look.');
      var st = serialStyle(soa.serial);
      if (st.kind === 'date') {
        var days = Math.floor((Date.now() - st.date.getTime()) / 86400000);
        add('pass', 'Serial ' + soa.serial + ' follows the YYYYMMDDnn convention: zone last revised on ' + st.text + ', revision ' + st.rev + (days >= 0 ? ' (' + days + ' day(s) ago)' : '') + '.');
        if (days < -1) add('warn', 'The serial date ' + st.text + ' is in the future.');
      } else if (st.kind === 'unix') add('info', 'Serial ' + soa.serial + ' looks like a Unix timestamp (' + st.text + '), which is a valid scheme.');
      else add('info', 'Serial ' + soa.serial + ' is a plain counter (not YYYYMMDDnn); that is fine, it only has to increase (RFC 1982).');
      if (soa.retry >= soa.refresh) add('warn', 'Retry (' + soa.retry + 's) is not smaller than refresh (' + soa.refresh + 's); retry is meant to be a shorter re-attempt interval.');
      if (soa.expire < soa.refresh + soa.retry) add('warn', 'Expire is shorter than refresh plus retry: secondaries could drop the zone before a refresh completes.');
      TIMERS.forEach(function (t) {
        var v = timerVerdict(t, soa[t.key]);
        if (v.level !== 'ok') add(v.level === 'warn' ? 'warn' : 'info', t.label + ' ' + soa[t.key] + 's (' + fmtDur(soa[t.key]) + '): ' + v.text + '.');
      });
      if (!/@/.test(decodeRname(soa.rname))) add('warn', 'The SOA admin mailbox "' + soa.rname + '" could not be decoded.');
    }

    // DNSSEC
    var sec = info.dnssec;
    if (sec.dsCount && sec.keyCount) {
      add(sec.ad ? 'pass' : 'warn', sec.ad ? 'DNSSEC: DS at the parent and DNSKEY in the zone; dns.google validated the answers (AD flag set).' : 'DS and DNSKEY exist but the resolver did not set AD on the answer: validation did not complete, check the chain of trust.');
      if (sec.weakAlg.length) add('warn', 'DNSSEC algorithm ' + sec.weakAlg.join(', ') + ' is SHA-1 based and not recommended (RFC 8624); move to 8, 13 or 15.');
      if (sec.dsDigests.length && sec.dsDigests.every(function (t) { return t === 1; })) add('warn', 'Every DS uses digest type 1 (SHA-1); add a SHA-256 (type 2) DS.');
    } else if (sec.dsCount && !sec.keyCount) add('fail', 'A DS record exists at the parent but the zone publishes no DNSKEY: resolvers that validate will fail this domain.');
    else if (!sec.dsCount && sec.keyCount) add('warn', 'The zone publishes DNSKEY records but there is no DS at the parent: it is signed but the chain of trust is not established.');
    else add('info', 'The zone is not signed with DNSSEC (no DS at the parent, no DNSKEY).');
    if (sec.bogus) add('fail', 'dns.google returned SERVFAIL but answered with validation disabled (CD): the zone fails DNSSEC validation (bogus signatures or a stale DS).');

    // Cross-resolver
    var x = info.cross;
    if (x.state === 'unavailable') add('info', 'Cross-check with cloudflare-dns.com was not possible (' + x.reason + ').');
    else {
      x.diffs.forEach(function (d) { add('warn', d); });
      if (!x.diffs.length) add('pass', 'dns.google and cloudflare-dns.com agree on the NS set, the SOA serial and the DS records.');
    }
    return checks;
  }

  // ---- Rendering ----
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  var views = { placeholder: $('placeholderState'), records: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }
  function section(title) {
    var s = el('section', 'sect');
    s.append(el('h3', 'sect-title', title));
    return s;
  }
  function table(headers, rows) {
    var wrap = el('div', 'tbl-scroll');
    wrap.tabIndex = 0;
    var t = el('table', 'tbl');
    var thead = el('thead'), hr = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; hr.append(th); });
    thead.append(hr); t.append(thead);
    var tb = el('tbody');
    rows.forEach(function (r) {
      var tr = el('tr');
      r.forEach(function (c, i) {
        var td = el('td');
        if (c && typeof c === 'object' && c.level) { td.append(el('span', 'chk ' + c.level, c.label)); td.append(' ' + c.text); }
        else td.textContent = c == null ? '' : String(c);
        if (i === 0) td.className = 'tbl-key';
        tr.append(td);
      });
      tb.append(tr);
    });
    t.append(tb); wrap.append(t);
    return wrap;
  }

  function renderResult(info, checks) {
    var box = views.records;
    box.replaceChildren();
    var worst = checks.some(function (c) { return c.level === 'fail'; }) ? 'fail'
      : checks.some(function (c) { return c.level === 'warn'; }) ? 'warn' : 'ok';
    var state = el('div', 'state ' + worst);
    state.append(el('h2', 'state-title', 'Delegation of'));
    state.append(el('span', 'badge-domain', info.domain));
    if (info.note) state.append(el('p', null, info.note));
    var providers = [];
    info.hosts.forEach(function (h) { var n = detectProvider(h); if (n && providers.indexOf(n) < 0) providers.push(n); });
    var pv = el('p', 'provider');
    if (providers.length) { pv.append('Detected DNS provider: '); pv.append(el('strong', null, providers.join(', '))); }
    else pv.append('DNS provider: not recognized from the nameserver names.');
    state.append(pv);
    box.append(state);

    // Name servers
    var sNs = section('Name servers (' + info.hosts.length + ')');
    var list = el('ul', 'record-list');
    info.hosts.forEach(function (h) {
      var li = el('li', 'mx-item');
      var head = el('div', 'mx-head');
      head.append(el('span', 'mx-host', h));
      var prov = detectProvider(h);
      if (prov) head.append(el('span', 'mx-role', prov));
      li.append(head);
      var r = info.resolved[h];
      var ad = el('div', 'mx-addrs');
      if (r.literal) ad.append(el('span', 'bad', 'IP literal, not a hostname'));
      else {
        var parts = [];
        if (r.cname) parts.push('CNAME → ' + r.cname);
        parts = parts.concat(r.a, r.aaaa);
        if (r.error || !parts.length) ad.append(el('span', 'bad', r.error || 'no address records'));
        else ad.textContent = parts.join('  ·  ') + (r.aaaa.length ? '' : '  (no IPv6)');
      }
      li.append(ad);
      list.append(li);
    });
    sNs.append(list);
    box.append(sNs);

    // SOA
    var soa = info.soa;
    var sSoa = section('SOA record');
    if (!soa) sSoa.append(el('p', 'block-note', 'No SOA record was returned.'));
    else {
      var st = serialStyle(soa.serial);
      var serialText = String(soa.serial) + (st.kind === 'date' ? '  (YYYYMMDDnn: ' + st.text + ', revision ' + st.rev + ')' : st.kind === 'unix' ? '  (Unix time: ' + st.text + ')' : '  (counter)');
      sSoa.append(table(['Field', 'Value'], [
        ['Primary (MNAME)', soa.mname],
        ['Admin mailbox (RNAME)', decodeRname(soa.rname) + '  (' + soa.rname + ')'],
        ['Serial', serialText]
      ]));
      var rows = TIMERS.map(function (t) {
        var v = timerVerdict(t, soa[t.key]);
        return [t.label, soa[t.key] + 's (' + fmtDur(soa[t.key]) + ')', t.ripe + 's', t.rfc, { level: v.level === 'ok' ? 'pass' : v.level, label: v.level, text: v.text }];
      });
      sSoa.append(table(['Timer', 'Value', 'RIPE-203', 'RFC 1912', 'Verdict'], rows));
      sSoa.append(el('p', 'block-note', 'Verdicts accept anything between the lowest and the highest of the RFC 1912 range and the RIPE-203 value. The minimum field is the negative-caching TTL since RFC 2308, so shorter values are accepted.'));
    }
    box.append(sSoa);

    // DNSSEC
    var sec = info.dnssec;
    var sSec = section('DNSSEC');
    sSec.append(table(['Item', 'Value'], [
      ['Zone signed', sec.keyCount ? 'yes (' + sec.keyCount + ' DNSKEY: ' + sec.ksk + ' KSK, ' + sec.zsk + ' ZSK)' : 'no DNSKEY published'],
      ['DS at the parent', sec.dsCount ? sec.dsCount + ' record(s)' : 'none'],
      ['Validated by dns.google (AD)', sec.ad ? 'yes' : 'no']
    ]));
    var dsRows = sec.ds.map(function (d) {
      return ['key tag ' + d.tag, (ALG[d.alg] || 'algorithm ' + d.alg) + ' (' + d.alg + ')', (DIGEST[d.dtype] || 'digest ' + d.dtype) + ' (' + d.dtype + ')'];
    });
    if (dsRows.length) sSec.append(table(['DS', 'Algorithm', 'Digest'], dsRows));
    box.append(sSec);

    // Cross-resolver
    var x = info.cross;
    var sX = section('Second opinion: cloudflare-dns.com');
    if (x.state === 'unavailable') sX.append(el('p', 'block-note', 'Not available: ' + x.reason + '.'));
    else sX.append(table(['Item', 'dns.google', 'cloudflare-dns.com', 'Result'], x.rows));
    sX.append(el('p', 'block-note', 'Both are independent recursive resolvers that fetch the answers from the authoritative servers. Agreement shows both see the same data right now; a difference can come from cache age or from authoritative servers that disagree. It does not prove that every individual nameserver is correct.'));
    box.append(sX);

    // Checks
    var ul = el('ul', 'checks');
    var labels = { pass: 'ok', warn: 'warn', fail: 'fail', info: 'note' };
    var order = { fail: 0, warn: 1, info: 2, pass: 3 };
    checks.slice().sort(function (a, b) { return order[a.level] - order[b.level]; }).forEach(function (c) {
      var li = el('li');
      li.append(el('span', 'chk ' + c.level, labels[c.level]));
      li.append(el('span', null, c.text));
      ul.append(li);
    });
    var sC = section('Checks');
    sC.append(ul);
    box.append(sC);
    box.append(siblingLinks(info.domain));
  }

  function siblingLinks(domain) {
    var wrap = el('p', 'provider');
    wrap.append('Also check ' + domain + ': ');
    [['dnssec', 'DNSSEC'], ['mx', 'MX'], ['spf', 'SPF'], ['dmarc', 'DMARC'], ['caa', 'CAA'], ['rdap', 'RDAP'], ['ssl', 'SSL'], ['ip', 'IP']].forEach(function (t, i) {
      if (i) wrap.append(' · ');
      var a = el('a', 'link', t[1]);
      a.href = 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(domain);
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      wrap.append(a);
    });
    return wrap;
  }

  function renderError(domain, msg) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', domain ? 'Error checking ' + domain : 'Error'));
    s.append(el('p', null, msg));
    box.append(s);
  }

  // ---- Lookup flow ----
  var domainInput = $('domainInput'), checkBtn = $('checkBtn'), btnText = $('btnText'), btnLoader = $('btnLoader');
  function setLoading(on) {
    checkBtn.disabled = on;
    btnText.textContent = on ? 'Checking' : 'Check delegation';
    btnLoader.hidden = !on;
    btnLoader.className = on ? 'loader' : '';
  }

  function summarizeSOA(d) { var a = answers(d, 6)[0]; return a ? parseSOA(a.data) : null; }
  function dsList(d) { return answers(d, 43).map(function (x) { return parseDS(x.data); }).filter(Boolean); }
  function keyList(d) { return answers(d, 48).map(function (x) { return parseDNSKEY(x.data); }).filter(Boolean); }

  async function crossCheck(domain, g) {
    var cf;
    try { cf = await queryZone(CLOUDFLARE, domain); }
    catch (e) { return { state: 'unavailable', reason: e.message }; }
    if (!cf.ns && !cf.soa) return { state: 'unavailable', reason: 'the request was blocked or failed' };
    var gNs = uniq(nsSet(g.ns)).sort(), cNs = uniq(nsSet(cf.ns)).sort();
    var gSoa = summarizeSOA(g.soa), cSoa = summarizeSOA(cf.soa);
    var key = function (d) { return d.tag + '/' + d.alg + '/' + d.dtype; };
    var gDs = dsList(g.ds).map(key).sort(), cDs = dsList(cf.ds).map(key).sort();
    var diffs = [];
    if (cf.ns && cf.ns.Status !== 0 && g.ns && g.ns.Status === 0) diffs.push('cloudflare-dns.com answered the NS query with DNS status ' + cf.ns.Status + (cf.ns.Status === 2 ? ' (SERVFAIL, consistent with a DNSSEC validation failure or unreachable servers)' : '') + ' while dns.google got an answer' + (g.bogus ? ' only with validation disabled' : '') + '.');
    if (cNs.length && gNs.join(',') !== cNs.join(',')) diffs.push('The NS set differs between resolvers (dns.google: ' + gNs.join(', ') + '; cloudflare-dns.com: ' + cNs.join(', ') + '). Possible stale cache after a change, or inconsistent authoritative servers.');
    if (gSoa && cSoa && gSoa.serial !== cSoa.serial) diffs.push('The SOA serial differs: dns.google sees ' + gSoa.serial + ', cloudflare-dns.com sees ' + cSoa.serial + '. Either one resolver has an older cached copy or the authoritative servers serve different zone versions (the classic sign of a failing zone transfer).');
    if (gSoa && cSoa && gSoa.mname !== cSoa.mname) diffs.push('The SOA primary differs between resolvers (' + gSoa.mname + ' vs ' + cSoa.mname + ').');
    if (gDs.join(',') !== cDs.join(',')) diffs.push('The DS records differ between resolvers.');
    var cmp = function (a, b) { return a === b ? 'same' : 'differs'; };
    var rows = [
      ['NS set', gNs.length + ' names', cNs.length + ' names', cmp(gNs.join(','), cNs.join(','))],
      ['SOA serial', gSoa ? String(gSoa.serial) : 'none', cSoa ? String(cSoa.serial) : 'none', cmp(gSoa && gSoa.serial, cSoa && cSoa.serial)],
      ['DS records', String(gDs.length), String(cDs.length), cmp(gDs.join(','), cDs.join(','))],
      ['AD flag (validated)', g.soa && g.soa.AD ? 'yes' : 'no', cf.soa && cf.soa.AD ? 'yes' : 'no', 'informational']
    ];
    return { state: 'done', diffs: diffs, rows: rows };
  }

  async function performLookup() {
    var domain = normalizeDomain(domainInput.value);
    if (!domain) { setView('error'); renderError('', 'Please enter a domain name'); return; }
    if (!validDomain(domain)) { setView('error'); renderError(domain, 'That is not a valid domain name.'); return; }
    domainInput.value = domain;
    setLoading(true);
    try {
      var note = null;
      var g = await queryZone(GOOGLE, domain);
      if (!g.ns) throw new Error('DNS query failed or was blocked.');
      var bogus = false;
      if (g.ns.Status === 2) {
        // SERVFAIL: retry with DNSSEC validation disabled to tell a validation failure from a broken zone.
        var cd = await safe(doh(GOOGLE, domain, 'NS', true));
        if (cd && cd.Status === 0 && nsSet(cd).length) { bogus = true; g.bogus = true; g.ns = cd; g.soa = await safe(doh(GOOGLE, domain, 'SOA', true)); g.ds = await safe(doh(GOOGLE, domain, 'DS', true)); g.dnskey = await safe(doh(GOOGLE, domain, 'DNSKEY', true)); }
        else throw new Error('SERVFAIL: the resolver could not get an answer for ' + domain + ' (all nameservers failing or unreachable, even with DNSSEC validation disabled).');
      }
      if (g.ns.Status === 3) throw new Error('Domain "' + domain + '" does not exist (NXDOMAIN)');
      if (g.ns.Status !== 0) throw new Error('DNS lookup error: ' + (g.ns.Comment || 'code ' + g.ns.Status));

      var hosts = nsSet(g.ns);
      if (!hosts.length) {
        // Not a zone apex: the authority section names the enclosing zone.
        var auth = (g.ns.Authority || []).filter(function (x) { return x.type === 6; })[0];
        var zone = auth ? stripDot(auth.name) : '';
        if (zone && zone !== domain && validDomain(zone) && domain.slice(-zone.length - 1) === '.' + zone) {
          note = domain + ' is not a zone apex (no NS records of its own); showing the delegation of the enclosing zone ' + zone + '.';
          domain = zone;
          g = await queryZone(GOOGLE, domain);
          if (!g.ns) throw new Error('DNS query failed or was blocked.');
          hosts = nsSet(g.ns);
        }
        if (!hosts.length) throw new Error('No NS records found for ' + domain + '. The name may exist as a host without being a delegated zone.');
      }

      var list = uniq(hosts).slice(0, MAX_NS);
      var resolved = {};
      var jobs = list.map(function (h) { return resolveHost(h).then(function (x) { resolved[h] = x; }); });
      var crossJob = crossCheck(domain, g);
      await Promise.all(jobs);
      var cross = await crossJob;

      var ds = dsList(g.ds), keys = keyList(g.dnskey);
      var algs = ds.map(function (d) { return d.alg; }).concat(keys.map(function (k) { return k.alg; }));
      var info = {
        domain: domain, note: note, hosts: list, resolved: resolved,
        soa: summarizeSOA(g.soa), cross: cross,
        dnssec: {
          ds: ds, dsCount: ds.length, keyCount: keys.length,
          ksk: keys.filter(function (k) { return k.flags & 1; }).length,
          zsk: keys.filter(function (k) { return !(k.flags & 1); }).length,
          ad: !!(g.soa && g.soa.AD) || !!(g.ds && g.ds.AD && ds.length),
          bogus: bogus,
          weakAlg: uniq(algs.filter(function (a) { return a === 5 || a === 7; })),
          dsDigests: ds.map(function (d) { return d.dtype; })
        }
      };
      if (hosts.length > MAX_NS) info.note = (info.note ? info.note + ' ' : '') + 'Only the first ' + MAX_NS + ' of ' + uniq(hosts).length + ' nameservers were resolved.';
      renderResult(info, buildChecks(info));
      setView('records');
    } catch (err) {
      renderError(domain, err.message || 'Unknown error');
      setView('error');
    } finally {
      setLoading(false);
    }
  }
  checkBtn.addEventListener('click', performLookup);
  domainInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') performLookup(); });

  setView('placeholder');
  var param = new URLSearchParams(window.location.search).get('domain');
  if (param) { domainInput.value = param; performLookup(); }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
