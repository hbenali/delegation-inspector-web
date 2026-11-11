# Delegation Checker

A free, single-page DNS delegation inspector. Live at [delegation.hbenali.ovh](https://delegation.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling public DNS-over-HTTPS APIs from the browser.

## Features

- **NS records** of the zone, each nameserver resolved to A and AAAA
- **Nameserver checks**: at least two (RFC 2182), different networks (IPv4 /24, IPv6 /48), at least one IPv6, no NS that is a CNAME or an IP literal, every NS name exists, private addresses
- **SOA**: primary, admin mailbox decoded, serial (YYYYMMDDnn, Unix time or counter detected), refresh/retry/expire/minimum checked against RFC 1912 and RIPE-203
- **DNSSEC**: DS at the parent, DNSKEY (KSK/ZSK), AD flag, weak algorithms and digests, bogus-zone detection (SERVFAIL that succeeds with CD)
- **DNS provider detection** from NS hostnames (Cloudflare, Route 53, Google Cloud DNS, OVHcloud, Gandi, Azure, NS1, DigitalOcean and others)
- **Second opinion**: the same NS/SOA/DS questions are sent to `dns.google` and `cloudflare-dns.com` and compared
- Cross-links to the DNSSEC, MX, SPF, DMARC, CAA, RDAP, SSL and IP tools for the same domain
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## What a browser cannot do

A web page cannot send queries to authoritative servers (no raw UDP/TCP), so these checks are **not** possible and the UI says so: lame-delegation tests, parent-versus-child NS comparison, and per-nameserver SOA serial comparison. The two-resolver comparison shows that both resolvers currently see the same data; a difference means cache age or disagreeing authoritative servers, and agreement does not prove each nameserver is healthy. Use `dig +trace` or `delv` for those.

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

`?domain=example.com` runs a lookup on load.

## Data sources

- [dns.google](https://developers.google.com/speed/public-dns/docs/doh): DNS-over-HTTPS (NS, SOA, DS, DNSKEY, A, AAAA)
- [cloudflare-dns.com](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/): second opinion (NS, SOA, DS, DNSKEY)

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
