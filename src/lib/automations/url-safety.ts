import net from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';

// ------------------------------------------------------------
// Outbound-HTTP SSRF defence for user-controlled URLs.
//
// The automations engine's `send_webhook` step lets users POST to
// arbitrary URLs they configured. Without filtering, a self-hosted
// deployment is a confused deputy: the server happily fetches
// http://169.254.169.254/latest/meta-data/, http://10.x.y.z/admin,
// or any other private CIDR reachable from the host.
//
// RESIDUAL RISK: this is resolve-time validation. A DNS rebinding
// attack — where the attacker's DNS server returns a public IP at
// resolve time and a private IP at connect time — defeats this
// check. Full mitigation requires a custom http(s).Agent that
// re-checks the socket peer address. Not implemented today; treat
// outbound send_webhook as semi-trusted.
// ------------------------------------------------------------

/**
 * Returns true if the given IP literal falls inside a CIDR range we
 * refuse to send outbound HTTP to. Unparseable input fails closed
 * (returns true). This is the trust boundary for outbound HTTP in
 * automation send_webhook steps.
 *
 * Blocked CIDRs:
 *   IPv4: 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
 *         172.16.0.0/12, 192.168.0.0/16
 *   IPv6: ::1 (loopback), fc00::/7 (ULA), fe80::/10 (link-local)
 */
export function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  const stripped = ip.replace(/^\[|\]$/g, '');
  const v = net.isIP(stripped);
  if (v === 4) return isPrivateIpv4(stripped);
  if (v === 6) return isPrivateIpv6(stripped);
  return true;
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number(p));
  if (
    parts.length !== 4 ||
    parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)
  ) {
    return true;
  }
  const n =
    ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  // 0.0.0.0/8 — "this host on this network"
  if (n >= 0x00_00_00_00 && n <= 0x00_ff_ff_ff) return true;
  // 10.0.0.0/8 — RFC1918
  if (n >= 0x0a_00_00_00 && n <= 0x0a_ff_ff_ff) return true;
  // 127.0.0.0/8 — loopback
  if (n >= 0x7f_00_00_00 && n <= 0x7f_ff_ff_ff) return true;
  // 169.254.0.0/16 — link-local + cloud metadata IPs
  if (n >= 0xa9_fe_00_00 && n <= 0xa9_fe_ff_ff) return true;
  // 172.16.0.0/12 — RFC1918
  if (n >= 0xac_10_00_00 && n <= 0xac_1f_ff_ff) return true;
  // 192.168.0.0/16 — RFC1918
  if (n >= 0xc0_a8_00_00 && n <= 0xc0_a8_ff_ff) return true;
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;
  // fc00::/7 — ULA. First byte is 0xfc or 0xfd.
  if (/^fc[0-9a-f]{2}:/.test(lower) || /^fd[0-9a-f]{2}:/.test(lower)) {
    return true;
  }
  // fe80::/10 — link-local. First 10 bits 1111111010 → first nibble
  // pair starts fe8x, fe9x, feax, febx.
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
  return false;
}

// Hostnames that must be rejected without ever doing a DNS lookup.
// Some resolvers map these to a public IP for advertising, which
// would otherwise bypass the literal-IP check below.
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
]);

/**
 * Validate a user-supplied URL is safe for the server to fetch:
 *   - protocol MUST be http or https
 *   - hostname literal IPs MUST NOT fall in any private CIDR
 *   - hostname names MUST resolve (via DNS) only to public IPs
 *   - blocked hostname literals like "localhost" are refused without DNS
 *
 * @throws on any failure. Returns the parsed URL on success.
 */
export async function assertPublicHttpUrl(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`URL is not a valid URL: ${rawUrl}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`URL must use http or https, got ${url.protocol}`);
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (BLOCKED_HOSTNAMES.has(host)) {
    throw new Error(`URL host is blocked (private): ${host}`);
  }

  // If hostname is already an IP literal, no DNS lookup needed.
  if (net.isIP(host) > 0) {
    if (isPrivateIp(host)) {
      throw new Error(`URL host is in a blocked range (private): ${host}`);
    }
    return url;
  }

  // Hostname is a name — resolve to all A/AAAA records and reject if
  // any one of them is in a blocked range. A single private record is
  // enough to refuse the request.
  let records: { address: string; family: number }[];
  try {
    const result = await dnsLookup(host, { all: true, verbatim: true });
    records = Array.isArray(result) ? result : [result];
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`URL hostname did not resolve: ${msg}`);
  }
  for (const r of records) {
    if (isPrivateIp(r.address)) {
      throw new Error(
        `URL resolves to a blocked range (private): ${r.address}`
      );
    }
  }
  return url;
}
