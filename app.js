// pages/api/bypass.js
import dns from "dns";
import net from "net";

const dnsLookup = dns.promises.lookup;

const MAX_HOPS = 10;
const REQUEST_TIMEOUT_MS = 10000; // per-request timeout
const MAX_TOTAL_TIME_MS = 25000; // optional overall safety

function isPrivateIPv4(addr) {
  // addr is like "10.0.0.1" or "192.168.0.1"
  if (!addr) return false;
  if (addr.startsWith("10.")) return true;
  if (addr.startsWith("127.")) return true; // loopback
  if (addr.startsWith("169.254.")) return true; // link-local
  if (addr.startsWith("192.168.")) return true;
  // 172.16.0.0 — 172.31.255.255
  if (addr.startsWith("172.")) {
    const parts = addr.split(".");
    if (parts.length >= 2) {
      const second = parseInt(parts[1], 10);
      if (second >= 16 && second <= 31) return true;
    }
  }
  return false;
}

function isPrivateIPv6(addr) {
  if (!addr) return false;
  // ::1 loopback
  if (addr === "::1") return true;
  // Unique local addresses: fc00::/7 (starts with fc or fd)
  if (addr.startsWith("fc") || addr.startsWith("fd")) return true;
  // link-local fe80::/10
  if (addr.startsWith("fe80")) return true;
  return false;
}

async function ensureNotPrivate(hostname) {
  // If hostname is an IP literal, check directly.
  if (net.isIP(hostname)) {
    if (net.isIP(hostname) === 4 && isPrivateIPv4(hostname)) {
      throw new Error("Refusing to resolve private/internal IPv4 address");
    }
    if (net.isIP(hostname) === 6 && isPrivateIPv6(hostname.toLowerCase())) {
      throw new Error("Refusing to resolve private/internal IPv6 address");
    }
    return;
  }

  // Otherwise do DNS lookup to get an IP and check it.
  // Note: using A/AAAA lookup via dns.lookup which may return IPv4/IPv6.
  try {
    const lookupResult = await dnsLookup(hostname, { all: true });
    if (!Array.isArray(lookupResult) || lookupResult.length === 0) {
      throw new Error("DNS lookup failed");
    }

    for (const r of lookupResult) {
      const addr = r.address;
      if (r.family === 4 && isPrivateIPv4(addr)) {
        throw new Error("Refusing to resolve to private/internal IPv4 address");
      }
      if (r.family === 6 && isPrivateIPv6(addr.toLowerCase())) {
        throw new Error("Refusing to resolve to private/internal IPv6 address");
      }
    }
  } catch (err) {
    // Fail closed on DNS errors to avoid SSRF via DNS tricks.
    throw new Error("DNS lookup error or result indicates private address: " + (err.message || err));
  }
}

export default async function handler(req, res) {
  const startTime = Date.now();

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ ok: false, error: "Method not allowed. Use GET /api/bypass?url=" });
  }

  const rawUrl = (req.query && req.query.url) || "";
  if (!rawUrl || typeof rawUrl !== "string") {
    return res.status(400).json({ ok: false, error: "Missing ?url= parameter" });
  }

  // Basic validation
  if (!/^https?:\/\//i.test(rawUrl)) {
    return res.status(400).json({ ok: false, error: "URL must start with http:// or https://" });
  }

  let current;
  try {
    current = new URL(rawUrl).toString();
  } catch (err) {
    return res.status(400).json({ ok: false, error: "Invalid URL" });
  }

  const chain = [];

  try {
    for (let hop = 0; hop < MAX_HOPS; hop++) {
      // Safety: overall time cap
      if (Date.now() - startTime > MAX_TOTAL_TIME_MS) {
        return res.status(500).json({ ok: false, error: "Overall timeout reached", chain });
      }

      // Before fetching, check hostname is not internal/private to prevent SSRF
      const urlObj = new URL(current);
      await ensureNotPrivate(urlObj.hostname);

      // Per-request timeout using AbortController
      const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
      const signal = controller ? controller.signal : undefined;
      let timeoutId;
      if (controller) {
        timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      }

      let resp;
      try {
        resp = await fetch(current, { method: "GET", redirect: "manual", signal });
      } catch (err) {
        const name = err && err.name ? err.name : "";
        if (name === "AbortError") {
          chain.push({ url: current, status: null, error: "request timed out" });
          return res.status(504).json({ ok: false, error: "Request timed out", chain });
        }
        chain.push({ url: current, status: null, error: String(err) });
        return res.status(502).json({ ok: false, error: "Fetch error: " + String(err), chain });
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }

      const status = resp.status;
      const location = resp.headers.get("location");
      chain.push({ url: current, status, location: location || null });

      // If redirect (3xx) and has Location header, resolve and continue
      if (status >= 300 && status < 400 && location) {
        // Resolve relative Location headers
        let next;
        try {
          next = new URL(location, current).toString();
        } catch (e) {
          // Malformed location header — stop and return chain so far
          return res.status(200).json({
            ok: true,
            finalUrl: current,
            finalStatus: status,
            chain,
            note: "Malformed Location header; stopped following.",
          });
        }

        // Prevent redirect loops: if next is same as last visited
        if (chain.some((c) => c.url === next)) {
          return res.status(200).json({
            ok: true,
            finalUrl: next,
            finalStatus: status,
            chain,
            note: "Detected redirect loop; stopped.",
          });
        }

        current = next;
        continue;
      }

      // Not a redirect — treat as final
      return res.status(200).json({
        ok: true,
        finalUrl: current,
        finalStatus: status,
        chain,
      });
    }

    // Reached MAX_HOPS
    return res.status(200).json({
      ok: true,
      finalUrl: chain.length ? chain[chain.length - 1].url : current,
      finalStatus: chain.length ? chain[chain.length - 1].status : null,
      chain,
      note: `stopped after ${MAX_HOPS} hops`,
    });
  } catch (err) {
    // expose a safe error message
    const msg = err && err.message ? err.message : String(err);
    return res.status(500).json({ ok: false, error: msg, chain });
  }
}
