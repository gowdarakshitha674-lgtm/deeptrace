import dns from "dns/promises";
import fs from "fs";
import net from "net";
import path from "path";
import crypto from "crypto";
import {
  computePerceptualHash,
  perceptualSimilarity,
  sha256Buffer,
  similarityLabel,
} from "./forensics.ts";
import { SOURCES_DIR } from "./store.ts";

const MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024;
const MAX_URLS_PER_REQUEST = 8;

const ALLOWED_CONTENT_TYPES: Record<string, string> = {
  "image/jpeg": ".jpg",
  "image/jpg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
  "image/bmp": ".bmp",
  "video/mp4": ".mp4",
  "video/webm": ".webm",
  "video/quicktime": ".mov",
  "audio/wav": ".wav",
  "audio/x-wav": ".wav",
  "audio/mpeg": ".mp3",
  "audio/mp4": ".m4a",
  "audio/ogg": ".ogg",
  "audio/flac": ".flac",
};

function isPrivateOrReservedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const norm = ip.toLowerCase();
    if (norm === "::1" || norm === "::") return true;
    if (norm.startsWith("fc") || norm.startsWith("fd")) return true;
    if (norm.startsWith("fe80")) return true;
    if (norm.startsWith("::ffff:")) {
      return isPrivateOrReservedIp(norm.slice(7));
    }
    return false;
  }
  return true;
}

export async function validatePublicHttpsUrl(rawUrl: string): Promise<{ ok: true; url: URL } | { ok: false; error: string }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { ok: false, error: "Invalid URL format." };
  }
  if (parsed.protocol !== "https:") {
    return { ok: false, error: "Only public HTTPS URLs are permitted." };
  }
  if (!parsed.hostname) {
    return { ok: false, error: "URL hostname is missing." };
  }
  const lower = parsed.hostname.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".local") || lower.endsWith(".internal")) {
    return { ok: false, error: "Loopback and local hostnames are blocked (SSRF protection)." };
  }
  if (net.isIP(lower)) {
    if (isPrivateOrReservedIp(lower)) {
      return { ok: false, error: "Private or reserved IP addresses are blocked (SSRF protection)." };
    }
    return { ok: true, url: parsed };
  }

  try {
    const records = await dns.lookup(lower, { all: true });
    if (records.length === 0) {
      return { ok: false, error: "Hostname could not be resolved." };
    }
    for (const rec of records) {
      if (isPrivateOrReservedIp(rec.address)) {
        return { ok: false, error: "Hostname resolved to a private/loopback IP address (SSRF protection)." };
      }
    }
    return { ok: true, url: parsed };
  } catch {
    return { ok: false, error: "Host could not be resolved via DNS." };
  }
}

export function parseSourceUrls(raw: unknown): string[] {
  if (Array.isArray(raw)) {
    return raw
      .filter((x): x is string => typeof x === "string")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, MAX_URLS_PER_REQUEST);
  }
  if (typeof raw === "string") {
    return raw
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, MAX_URLS_PER_REQUEST);
  }
  return [];
}

export async function fetchAndComparePublicUrl(params: {
  investigationId: number;
  rawUrl: string;
  originalSha256: string;
  originalPerceptualHash: string | null;
}) {
  const { investigationId, rawUrl, originalSha256, originalPerceptualHash } = params;
  const validation = await validatePublicHttpsUrl(rawUrl);
  if (!validation.ok) {
    return {
      source_url: rawUrl,
      origin: "public_url" as const,
      retrieval_status: "rejected" as const,
      retrieval_error: validation.error,
      file_path: null,
      content_type: null,
      bytes_downloaded: null,
      sha256_hash: null,
      perceptual_hash: null,
      similarity: null,
      match_type: null,
      similarity_label: null,
    };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const res = await fetch(validation.url.toString(), {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: { "User-Agent": "DeepTrace/1.0 (+local forensic trace)" },
    });
    clearTimeout(timer);

    if (res.status >= 300 && res.status < 400) {
      return {
        source_url: rawUrl,
        origin: "public_url" as const,
        retrieval_status: "rejected" as const,
        retrieval_error: `Redirect (${res.status}) declined for strict SSRF containment.`,
        file_path: null,
        content_type: null,
        bytes_downloaded: null,
        sha256_hash: null,
        perceptual_hash: null,
        similarity: null,
        match_type: null,
        similarity_label: null,
      };
    }

    if (!res.ok) {
      return {
        source_url: rawUrl,
        origin: "public_url" as const,
        retrieval_status: "failed" as const,
        retrieval_error: `Remote server returned HTTP ${res.status}.`,
        file_path: null,
        content_type: null,
        bytes_downloaded: null,
        sha256_hash: null,
        perceptual_hash: null,
        similarity: null,
        match_type: null,
        similarity_label: null,
      };
    }

    const contentType = (res.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    const ext = ALLOWED_CONTENT_TYPES[contentType];
    if (!ext) {
      return {
        source_url: rawUrl,
        origin: "public_url" as const,
        retrieval_status: "rejected" as const,
        retrieval_error: `Refused non-media Content-Type (${contentType || "unknown"}) so HTML/error pages are never hashed as evidence.`,
        file_path: null,
        content_type: contentType || null,
        bytes_downloaded: null,
        sha256_hash: null,
        perceptual_hash: null,
        similarity: null,
        match_type: null,
        similarity_label: null,
      };
    }

    const arrayBuf = await res.arrayBuffer();
    if (arrayBuf.byteLength > MAX_DOWNLOAD_BYTES) {
      return {
        source_url: rawUrl,
        origin: "public_url" as const,
        retrieval_status: "rejected" as const,
        retrieval_error: "Remote media exceeded the 25 MB retrieval cap.",
        file_path: null,
        content_type: contentType,
        bytes_downloaded: arrayBuf.byteLength,
        sha256_hash: null,
        perceptual_hash: null,
        similarity: null,
        match_type: null,
        similarity_label: null,
      };
    }

    const buf = Buffer.from(arrayBuf);
    const dir = path.join(SOURCES_DIR, `case_${investigationId}`);
    fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, `${crypto.randomUUID()}${ext}`);
    fs.writeFileSync(filePath, buf);

    const sha256 = sha256Buffer(buf);
    const pHash = await computePerceptualHash(filePath);
    let sim: number | null = null;
    let matchType: string | null = null;

    if (sha256 === originalSha256) {
      sim = 1.0;
      matchType = "exact";
    } else {
      sim = perceptualSimilarity(originalPerceptualHash, pHash);
      if (sim !== null) {
        matchType = sim >= 0.78 ? "near" : "none";
      }
    }

    return {
      source_url: rawUrl,
      origin: "public_url" as const,
      retrieval_status: "fetched" as const,
      retrieval_error: null,
      file_path: filePath,
      content_type: contentType,
      bytes_downloaded: buf.byteLength,
      sha256_hash: sha256,
      perceptual_hash: pHash,
      similarity: sim,
      match_type: matchType,
      similarity_label: similarityLabel(sim),
    };
  } catch (err) {
    return {
      source_url: rawUrl,
      origin: "public_url" as const,
      retrieval_status: "failed" as const,
      retrieval_error: err instanceof Error ? err.message : "Network error during retrieval.",
      file_path: null,
      content_type: null,
      bytes_downloaded: null,
      sha256_hash: null,
      perceptual_hash: null,
      similarity: null,
      match_type: null,
      similarity_label: null,
    };
  }
}
