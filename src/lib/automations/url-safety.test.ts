import { describe, expect, it, vi } from 'vitest';
import { isPrivateIp, assertPublicHttpUrl } from './url-safety';

describe('isPrivateIp', () => {
  it('flags IPv4 loopback range', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('127.255.255.254')).toBe(true);
  });

  it('flags IPv4 RFC1918 ranges', () => {
    expect(isPrivateIp('10.0.0.0')).toBe(true);
    expect(isPrivateIp('10.255.255.255')).toBe(true);
    expect(isPrivateIp('172.16.0.0')).toBe(true);
    expect(isPrivateIp('172.31.255.255')).toBe(true);
    expect(isPrivateIp('192.168.0.0')).toBe(true);
    expect(isPrivateIp('192.168.255.255')).toBe(true);
  });

  it('flags IPv4 link-local + AWS/GCP metadata IP', () => {
    expect(isPrivateIp('169.254.0.0')).toBe(true);
    expect(isPrivateIp('169.254.169.254')).toBe(true);
  });

  it('flags the IPv4 unspecified range (0.0.0.0/8)', () => {
    expect(isPrivateIp('0.0.0.0')).toBe(true);
    expect(isPrivateIp('0.255.255.255')).toBe(true);
  });

  it('does not flag public IPv4 addresses', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('1.1.1.1')).toBe(false);
    expect(isPrivateIp('172.15.255.255')).toBe(false); // just below 172.16/12
    expect(isPrivateIp('172.32.0.0')).toBe(false); // just above 172.31/12
    expect(isPrivateIp('11.0.0.0')).toBe(false);
    expect(isPrivateIp('192.169.0.0')).toBe(false);
  });

  it('flags IPv6 loopback and ULA / link-local ranges', () => {
    expect(isPrivateIp('::1')).toBe(true);
    expect(isPrivateIp('fe80::1')).toBe(true);
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('fdff::1')).toBe(true);
  });

  it('does not flag public IPv6 addresses', () => {
    expect(isPrivateIp('2606:4700:4700::1111')).toBe(false);
    expect(isPrivateIp('2001:4860:4860::8888')).toBe(false);
  });

  it('treats unparseable input as private (fail-closed)', () => {
    expect(isPrivateIp('not-an-ip')).toBe(true);
    expect(isPrivateIp('')).toBe(true);
  });
});

describe('assertPublicHttpUrl', () => {
  it('rejects non-http(s) protocols', async () => {
    await expect(assertPublicHttpUrl('ftp://example.com/x')).rejects.toThrow(
      /http or https/
    );
    await expect(assertPublicHttpUrl('file:///etc/passwd')).rejects.toThrow(
      /http or https/
    );
    await expect(assertPublicHttpUrl('javascript:alert(1)')).rejects.toThrow(
      /http or https/
    );
  });

  it('rejects malformed URLs', async () => {
    await expect(assertPublicHttpUrl('not a url')).rejects.toThrow();
  });

  it('rejects IPv4 literal hosts in private ranges without DNS', async () => {
    await expect(assertPublicHttpUrl('http://127.0.0.1/x')).rejects.toThrow(
      /blocked|private/i
    );
    await expect(
      assertPublicHttpUrl('http://169.254.169.254/latest/meta-data/')
    ).rejects.toThrow(/blocked|private/i);
    await expect(assertPublicHttpUrl('http://10.0.0.1/x')).rejects.toThrow(
      /blocked|private/i
    );
    await expect(assertPublicHttpUrl('http://192.168.1.1/x')).rejects.toThrow(
      /blocked|private/i
    );
  });

  it('rejects IPv6 literal loopback host', async () => {
    await expect(assertPublicHttpUrl('http://[::1]/x')).rejects.toThrow(
      /blocked|private/i
    );
  });

  it('rejects localhost hostname before any DNS call', async () => {
    await expect(assertPublicHttpUrl('http://localhost/x')).rejects.toThrow(
      /blocked|private/i
    );
    await expect(assertPublicHttpUrl('http://LOCALHOST/x')).rejects.toThrow(
      /blocked|private/i
    );
  });

  it('rejects hostnames that resolve to a private IP', async () => {
    // Mock DNS to return a private IP for a name that, in real DNS,
    // would be public. This is the DNS-rebinding-style attack surface:
    // user controls the hostname, attacker's DNS server points it at
    // a private CIDR at resolve time.
    vi.resetModules();
    vi.doMock('node:dns/promises', () => ({
      lookup: vi.fn(async () => [{ address: '10.0.0.5', family: 4 }]),
    }));
    const mod = await import('./url-safety');
    await expect(
      mod.assertPublicHttpUrl('http://attacker.example.com/x')
    ).rejects.toThrow(/blocked|private/i);
    vi.doUnmock('node:dns/promises');
    vi.resetModules();
  });

  it('returns a URL for hostnames that resolve only to public IPs', async () => {
    vi.resetModules();
    vi.doMock('node:dns/promises', () => ({
      lookup: vi.fn(async () => [{ address: '8.8.8.8', family: 4 }]),
    }));
    const mod = await import('./url-safety');
    const u = await mod.assertPublicHttpUrl('https://hooks.example.com/in');
    expect(u.toString()).toBe('https://hooks.example.com/in');
    vi.doUnmock('node:dns/promises');
    vi.resetModules();
  });
});
