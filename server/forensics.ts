import { execFile } from "child_process";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { PNG } from "pngjs";
import {
  AUDIO_DIR,
  FRAMES_DIR,
  LOCALIZATION_DIR,
  PROJECT_ROOT,
  resolveInside,
  type EvidenceRecord,
  type VoiceAudioProfile,
} from "./store.ts";

const execFileAsync = promisify(execFile);

export function sha256Buffer(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

export function sha256File(filePath: string): string {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  try {
    const chunk = Buffer.allocUnsafe(64 * 1024);
    let bytesRead = 0;
    while ((bytesRead = fs.readSync(fd, chunk, 0, chunk.length, null)) > 0) {
      hash.update(chunk.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

export async function checkFfmpegAvailable(): Promise<{ available: boolean; detail: string }> {
  try {
    const { stdout } = await execFileAsync("ffmpeg", ["-version"], { timeout: 4000 });
    const firstLine = stdout.split(/\r?\n/)[0] || "ffmpeg available";
    return { available: true, detail: firstLine };
  } catch {
    return { available: false, detail: "ffmpeg not found on PATH" };
  }
}

export interface MediaProbeResult {
  durationSeconds: number | null;
  resolution: string | null;
  fps: number | null;
  hasAudioStream: boolean | null;
  metadata: Record<string, unknown>;
}

function parseFraction(raw: string | undefined): number | null {
  if (!raw) return null;
  const parts = raw.split("/");
  if (parts.length === 2) {
    const num = Number(parts[0]);
    const den = Number(parts[1]);
    if (Number.isFinite(num) && Number.isFinite(den) && den > 0) {
      return Math.round((num / den) * 100) / 100;
    }
  }
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.round(n * 100) / 100 : null;
}

export async function probeMedia(
  filePath: string,
  mediaType: "video" | "image" | "audio"
): Promise<MediaProbeResult> {
  try {
    const { stdout } = await execFileAsync(
      "ffprobe",
      [
        "-v",
        "quiet",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
        filePath,
      ],
      { timeout: 10000 }
    );
    const parsed = JSON.parse(stdout) as {
      format?: Record<string, unknown>;
      streams?: Array<Record<string, unknown>>;
    };
    const streams = parsed.streams ?? [];
    const videoStream = streams.find((s) => s.codec_type === "video");
    const audioStream = streams.find((s) => s.codec_type === "audio");
    const durationRaw =
      (parsed.format?.duration as string | undefined) ??
      (videoStream?.duration as string | undefined) ??
      (audioStream?.duration as string | undefined);
    const durationSeconds =
      mediaType === "image"
        ? null
        : durationRaw && Number.isFinite(Number(durationRaw))
          ? Math.round(Number(durationRaw) * 1000) / 1000
          : null;

    const width = typeof videoStream?.width === "number" ? videoStream.width : null;
    const height = typeof videoStream?.height === "number" ? videoStream.height : null;
    const resolution = width && height ? `${width}x${height}` : null;
    const fps =
      mediaType === "video"
        ? parseFraction(
            (videoStream?.avg_frame_rate as string | undefined) ??
              (videoStream?.r_frame_rate as string | undefined)
          )
        : null;

    const hasAudioStream =
      mediaType === "image" ? false : Boolean(audioStream);

    return {
      durationSeconds,
      resolution,
      fps,
      hasAudioStream,
      metadata: {
        format_name: parsed.format?.format_name ?? null,
        bit_rate: parsed.format?.bit_rate ? Number(parsed.format.bit_rate) : null,
        video_codec: videoStream?.codec_name ?? null,
        audio_codec: audioStream?.codec_name ?? null,
        sample_rate: audioStream?.sample_rate ? Number(audioStream.sample_rate) : null,
        channels: audioStream?.channels ?? null,
        tags: parsed.format?.tags ?? {},
      },
    };
  } catch {
    return {
      durationSeconds: null,
      resolution: null,
      fps: null,
      hasAudioStream: mediaType === "image" ? false : null,
      metadata: { probe_note: "ffprobe unavailable or unreadable container" },
    };
  }
}

/**
 * Computes a 64-bit difference hash (dHash) by asking ffmpeg to resize the image
 * or video frame into a 9x8 raw grayscale buffer.
 */
export async function computePerceptualHash(mediaPath: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(
      "ffmpeg",
      [
        "-v",
        "error",
        "-i",
        mediaPath,
        "-vframes",
        "1",
        "-vf",
        "scale=9:8:flags=area,format=gray",
        "-f",
        "rawvideo",
        "pipe:1",
      ],
      { encoding: "buffer", timeout: 8000, maxBuffer: 1024 * 1024 }
    );
    const buf = stdout as unknown as Buffer;
    if (buf.length < 72) return null;

    let bits = BigInt(0);
    let bitIdx = 0;
    for (let y = 0; y < 8; y++) {
      for (let x = 0; x < 8; x++) {
        const left = buf[y * 9 + x];
        const right = buf[y * 9 + x + 1];
        if (left > right) {
          bits |= BigInt(1) << BigInt(63 - bitIdx);
        }
        bitIdx++;
      }
    }
    return bits.toString(16).padStart(16, "0");
  } catch {
    return null;
  }
}

export function perceptualSimilarity(hashA: string | null, hashB: string | null): number | null {
  if (!hashA || !hashB || hashA.length !== 16 || hashB.length !== 16) return null;
  try {
    let diff = BigInt(`0x${hashA}`) ^ BigInt(`0x${hashB}`);
    let dist = 0;
    while (diff > 0n) {
      dist += Number(diff & 1n);
      diff >>= 1n;
    }
    return Math.round((1 - dist / 64) * 10000) / 10000;
  } catch {
    return null;
  }
}

export function similarityLabel(score: number | null): string {
  if (score === null) return "Not compared";
  if (score >= 0.92) return "High similarity";
  if (score >= 0.78) return "Moderate similarity";
  return "Low similarity";
}

/**
 * Extracts a normalized 64-element visual spatial+color descriptor using ffmpeg 16x16 RGB
 * downsampling + center crop weighting for deterministic identity comparison.
 */
export async function computeVisualSignature(imagePath: string): Promise<number[] | null> {
  try {
    const { stdout } = await execFileAsync(
      "ffmpeg",
      [
        "-v",
        "error",
        "-i",
        imagePath,
        "-vframes",
        "1",
        "-vf",
        "crop=min(iw\\,ih):min(iw\\,ih),scale=8:8:flags=area,format=rgb24",
        "-f",
        "rawvideo",
        "pipe:1",
      ],
      { encoding: "buffer", timeout: 8000, maxBuffer: 1024 * 1024 }
    );
    const buf = stdout as unknown as Buffer;
    if (buf.length < 192) return null;

    const vec: number[] = [];
    let mean = 0;
    for (let i = 0; i < 64; i++) {
      const r = buf[i * 3];
      const g = buf[i * 3 + 1];
      const b = buf[i * 3 + 2];
      const luma = 0.299 * r + 0.587 * g + 0.114 * b;
      const chromaDiff = (r - b) * 0.35;
      const val = luma + chromaDiff;
      vec.push(val);
      mean += val;
    }
    mean /= vec.length;
    const centered = vec.map((v) => v - mean);
    const norm = Math.sqrt(centered.reduce((acc, v) => acc + v * v, 0));
    if (norm < 1e-6) return null;
    return centered.map((v) => Math.round((v / norm) * 1e6) / 1e6);
  } catch {
    return null;
  }
}

export function cosineSimilarity(a: number[] | null, b: number[] | null): number | null {
  if (!a || !b || a.length !== b.length || a.length === 0) return null;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  if (denom < 1e-8) return null;
  return Math.max(-1, Math.min(1, Math.round((dot / denom) * 1e6) / 1e6));
}

export async function extractSampledFrames(
  investigationId: number,
  videoPath: string,
  durationSeconds: number | null,
  maxSamples = 12
): Promise<Array<{ filePath: string; timestampOffset: number; sha256: string; pHash: string | null }>> {
  const outDir = path.join(FRAMES_DIR, `case_${investigationId}`);
  fs.mkdirSync(outDir, { recursive: true });

  const dur = durationSeconds && durationSeconds > 0 ? durationSeconds : 2.0;
  const count = Math.min(maxSamples, Math.max(3, Math.round(dur * 2)));
  const extracted: Array<{
    filePath: string;
    timestampOffset: number;
    sha256: string;
    pHash: string | null;
  }> = [];

  for (let i = 0; i < count; i++) {
    const ts = Math.max(0, Math.min(dur - 0.05, (dur * (i + 0.5)) / count));
    const framePath = path.join(outDir, `frame_${String(i).padStart(3, "0")}.png`);
    try {
      await execFileAsync(
        "ffmpeg",
        [
          "-y",
          "-v",
          "error",
          "-ss",
          ts.toFixed(3),
          "-i",
          videoPath,
          "-vframes",
          "1",
          "-vf",
          "scale='min(640,iw)':-2",
          framePath,
        ],
        { timeout: 10000 }
      );
      if (fs.existsSync(framePath) && fs.statSync(framePath).size > 0) {
        const sha256 = sha256File(framePath);
        const pHash = await computePerceptualHash(framePath);
        extracted.push({
          filePath: framePath,
          timestampOffset: Math.round(ts * 1000) / 1000,
          sha256,
          pHash,
        });
      }
    } catch {
      /* skip individual failed frame seek */
    }
  }
  return extracted;
}

export async function extractAudioTrack(
  investigationId: number,
  mediaPath: string
): Promise<{ filePath: string; sha256: string } | null> {
  const outDir = path.join(AUDIO_DIR, `case_${investigationId}`);
  fs.mkdirSync(outDir, { recursive: true });
  const wavPath = path.join(outDir, "extracted_16k_mono.wav");
  try {
    await execFileAsync(
      "ffmpeg",
      [
        "-y",
        "-v",
        "error",
        "-i",
        mediaPath,
        "-vn",
        "-ac",
        "1",
        "-ar",
        "16000",
        "-f",
        "wav",
        wavPath,
      ],
      { timeout: 15000 }
    );
    if (!fs.existsSync(wavPath) || fs.statSync(wavPath).size < 64) {
      return null;
    }
    return { filePath: wavPath, sha256: sha256File(wavPath) };
  } catch {
    return null;
  }
}

export async function analyzeAudioProfile(mediaPath: string): Promise<VoiceAudioProfile | null> {
  const tempWav = path.join(AUDIO_DIR, `probe_${Date.now()}_${Math.random().toString(16).slice(2)}.wav`);
  try {
    await execFileAsync(
      "ffmpeg",
      [
        "-y",
        "-v",
        "error",
        "-i",
        mediaPath,
        "-vn",
        "-ac",
        "1",
        "-ar",
        "16000",
        "-f",
        "s16le",
        tempWav,
      ],
      { timeout: 10000 }
    );
    if (!fs.existsSync(tempWav)) return null;
    const raw = fs.readFileSync(tempWav);
    const sampleCount = Math.floor(raw.length / 2);
    if (sampleCount < 400) return null;

    const samples = new Float32Array(sampleCount);
    let clipped = 0;
    let zc = 0;
    for (let i = 0; i < sampleCount; i++) {
      const s = raw.readInt16LE(i * 2) / 32768;
      samples[i] = s;
      if (Math.abs(s) >= 0.985) clipped++;
      if (i > 0 && ((samples[i - 1] >= 0 && s < 0) || (samples[i - 1] < 0 && s >= 0))) {
        zc++;
      }
    }

    const winSize = 1600; // 100ms windows
    const windowRms: number[] = [];
    for (let start = 0; start + winSize <= sampleCount; start += winSize) {
      let sumSq = 0;
      for (let j = 0; j < winSize; j++) {
        sumSq += samples[start + j] * samples[start + j];
      }
      windowRms.push(Math.sqrt(sumSq / winSize));
    }

    const rmsMean =
      windowRms.length > 0
        ? windowRms.reduce((a, b) => a + b, 0) / windowRms.length
        : 0;
    const rmsVar =
      windowRms.length > 0
        ? windowRms.reduce((a, b) => a + (b - rmsMean) ** 2, 0) / windowRms.length
        : 0;
    const rmsStd = Math.sqrt(rmsVar);

    let maxJump = 0;
    for (let i = 1; i < windowRms.length; i++) {
      maxJump = Math.max(maxJump, Math.abs(windowRms[i] - windowRms[i - 1]));
    }
    const discontinuityScore = Math.min(1, maxJump / Math.max(0.05, rmsMean + 0.05));

    // Coarse 8-bin temporal energy envelope for speaker profile signature
    const bandEnergies: number[] = [];
    const segLen = Math.max(1, Math.floor(sampleCount / 8));
    for (let b = 0; b < 8; b++) {
      let sum = 0;
      const start = b * segLen;
      const end = Math.min(sampleCount, start + segLen);
      for (let i = start; i < end; i++) {
        sum += Math.abs(samples[i]);
      }
      bandEnergies.push(Math.round((sum / Math.max(1, end - start)) * 1e5) / 1e5);
    }

    return {
      durationSeconds: Math.round((sampleCount / 16000) * 1000) / 1000,
      sampleRate: 16000,
      rmsMean: Math.round(rmsMean * 1e5) / 1e5,
      rmsStd: Math.round(rmsStd * 1e5) / 1e5,
      zeroCrossingRate: Math.round((zc / sampleCount) * 1e5) / 1e5,
      clippingRatio: Math.round((clipped / sampleCount) * 1e5) / 1e5,
      discontinuityScore: Math.round(discontinuityScore * 1e4) / 1e4,
      bandEnergies,
    };
  } catch {
    return null;
  } finally {
    if (fs.existsSync(tempWav)) {
      fs.unlinkSync(tempWav);
    }
  }
}

export interface FrameForensicOutcome {
  timestampOffset: number;
  score: number;
  residualEnergy: number;
  overlayPath: string;
  overlaySha256: string;
}

/**
 * Converts an image or frame to PNG via ffmpeg, computes Laplacian high-frequency
 * residual energy & spatial variance indicators, and writes a PNG residual heatmap.
 */
export async function analyzeFrameForensics(
  investigationId: number,
  sourcePath: string,
  index: number,
  timestampOffset: number
): Promise<FrameForensicOutcome | null> {
  const outDir = path.join(LOCALIZATION_DIR, `case_${investigationId}`);
  fs.mkdirSync(outDir, { recursive: true });
  const tempPng = path.join(outDir, `_src_${index}.png`);
  const overlayPath = path.join(outDir, `residual_${String(index).padStart(3, "0")}.png`);

  try {
    await execFileAsync(
      "ffmpeg",
      [
        "-y",
        "-v",
        "error",
        "-i",
        sourcePath,
        "-vframes",
        "1",
        "-vf",
        "scale='min(384,iw)':-2",
        tempPng,
      ],
      { timeout: 10000 }
    );
    if (!fs.existsSync(tempPng)) return null;

    const png = PNG.sync.read(fs.readFileSync(tempPng));
    const { width: w, height: h, data } = png;
    const gray = new Float32Array(w * h);
    for (let i = 0; i < w * h; i++) {
      const idx = i * 4;
      gray[i] = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2];
    }

    const overlay = new PNG({ width: w, height: h });
    let lapSum = 0;
    let lapSqSum = 0;
    let highEdgeCount = 0;
    const count = Math.max(1, (w - 2) * (h - 2));

    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const i = y * w + x;
        const idx = i * 4;
        if (x === 0 || y === 0 || x === w - 1 || y === h - 1) {
          overlay.data[idx] = Math.round(gray[i] * 0.35);
          overlay.data[idx + 1] = Math.round(gray[i] * 0.35);
          overlay.data[idx + 2] = Math.round(gray[i] * 0.35);
          overlay.data[idx + 3] = 255;
          continue;
        }
        const lap = Math.abs(
          4 * gray[i] - gray[i - 1] - gray[i + 1] - gray[i - w] - gray[i + w]
        );
        lapSum += lap;
        lapSqSum += lap * lap;
        if (lap > 36) highEdgeCount++;

        const amp = Math.min(255, lap * 3.2);
        const base = gray[i] * 0.32;
        overlay.data[idx] = Math.min(255, Math.round(base + amp));
        overlay.data[idx + 1] = Math.min(255, Math.round(base + amp * 0.38));
        overlay.data[idx + 2] = Math.min(255, Math.round(base + amp * 0.12));
        overlay.data[idx + 3] = 255;
      }
    }

    fs.writeFileSync(overlayPath, PNG.sync.write(overlay));
    const overlaySha256 = sha256File(overlayPath);

    const meanLap = lapSum / count;
    const varLap = Math.max(0, lapSqSum / count - meanLap * meanLap);
    const stdLap = Math.sqrt(varLap);
    const edgeRatio = highEdgeCount / count;

    // Heuristic signal combining uneven high-frequency dispersion & edge density.
    // Explicitly labeled as a non-ML frequency-residual heuristic in API/UI.
    const cv = stdLap / Math.max(1, meanLap);
    const rawScore = Math.max(0.08, Math.min(0.88, 0.22 * Math.min(2, cv / 1.8) + 0.45 * Math.min(1, edgeRatio * 4.5)));

    return {
      timestampOffset,
      score: Math.round(rawScore * 10000) / 10000,
      residualEnergy: Math.round(meanLap * 100) / 100,
      overlayPath,
      overlaySha256,
    };
  } catch {
    return null;
  } finally {
    if (fs.existsSync(tempPng)) {
      fs.unlinkSync(tempPng);
    }
  }
}

export function inspectC2paManifest(filePath: string): {
  status: "no_credentials" | "manifest_detected";
  details: string;
} {
  try {
    const fd = fs.openSync(filePath, "r");
    const size = Math.min(fs.statSync(filePath).size, 512 * 1024);
    const buf = Buffer.allocUnsafe(size);
    fs.readSync(fd, buf, 0, size, 0);
    fs.closeSync(fd);

    const text = buf.toString("latin1");
    if (text.includes("c2pa") || text.includes("urn:c2pa") || text.includes("jumb")) {
      return {
        status: "manifest_detected",
        details: "C2PA JUMBF container markers detected in file header bytes (cryptographic signature validation requires c2pa-python trust list).",
      };
    }
    return {
      status: "no_credentials",
      details: "No Content Credentials (C2PA) manifest markers were found in the file. Most legitimate media carries no C2PA metadata; absence does not indicate manipulation.",
    };
  } catch {
    return {
      status: "no_credentials",
      details: "Could not read file header for C2PA markers.",
    };
  }
}

export function verifyEvidenceArtifacts(evidenceRows: EvidenceRecord[], investigationId = 0) {
  let verified = 0;
  let mismatch = 0;
  let missing = 0;
  let noRecordedHash = 0;

  const artifacts = evidenceRows.map((row) => {
    const labelMap: Record<string, string> = {
      original: "Original submitted media",
      frame: "Sampled video frame",
      localization: "Manipulation overlay",
      audio: "Extracted audio track",
      traced_copy: "Traced external copy",
    };
    const label = labelMap[row.evidence_type] || row.evidence_type;
    const relPath = path.relative(PROJECT_ROOT, row.file_path).split(path.sep).join("/");

    if (!row.sha256_hash) {
      noRecordedHash++;
      return {
        evidence_id: row.id,
        evidence_type: row.evidence_type,
        label,
        public_path: relPath,
        timestamp_offset: row.timestamp_offset,
        preserved_at: row.created_at,
        status: "no_recorded_hash" as const,
        recorded_sha256: null,
        current_sha256: null,
        detail: "No digest was recorded when this artifact was preserved.",
      };
    }

    const safeTarget = resolveInside(PROJECT_ROOT, row.file_path);
    if (!safeTarget || !fs.existsSync(safeTarget)) {
      missing++;
      return {
        evidence_id: row.id,
        evidence_type: row.evidence_type,
        label,
        public_path: relPath,
        timestamp_offset: row.timestamp_offset,
        preserved_at: row.created_at,
        status: "missing" as const,
        recorded_sha256: row.sha256_hash,
        current_sha256: null,
        detail: "Recorded artifact file could not be read from disk.",
      };
    }

    const actual = sha256File(safeTarget);
    if (actual === row.sha256_hash) {
      verified++;
      return {
        evidence_id: row.id,
        evidence_type: row.evidence_type,
        label,
        public_path: relPath,
        timestamp_offset: row.timestamp_offset,
        preserved_at: row.created_at,
        status: "verified" as const,
        recorded_sha256: row.sha256_hash,
        current_sha256: actual,
        detail: "Current bytes on disk match the SHA-256 digest recorded at preservation.",
      };
    }

    mismatch++;
    return {
      evidence_id: row.id,
      evidence_type: row.evidence_type,
      label,
      public_path: relPath,
      timestamp_offset: row.timestamp_offset,
      preserved_at: row.created_at,
      status: "mismatch" as const,
      recorded_sha256: row.sha256_hash,
      current_sha256: actual,
      detail: "Current bytes on disk DO NOT match the recorded SHA-256 digest.",
    };
  });

  const total = evidenceRows.length;
  const chainIntact = total > 0 && mismatch === 0 && missing === 0;
  let summary = "";
  if (total === 0) {
    summary = "No preserved artifacts were recorded for this investigation.";
  } else if (chainIntact && noRecordedHash === 0) {
    summary = `All ${total} preserved artifact(s) re-hash to their recorded SHA-256 values. The evidence set is intact.`;
  } else if (chainIntact) {
    summary = `${verified} of ${total} artifact(s) re-hash to their recorded values; ${noRecordedHash} had no digest recorded at preservation time.`;
  } else {
    const problems: string[] = [];
    if (mismatch) problems.push(`${mismatch} hash mismatch(es)`);
    if (missing) problems.push(`${missing} missing file(s)`);
    summary = `Integrity check FAILED: ${problems.join(" and ")} out of ${total} artifact(s).`;
  }

  return {
    investigation_id: investigationId,
    verified_at: new Date().toISOString(),
    algorithm: "SHA-256",
    artifacts_checked: total,
    counts: {
      verified,
      mismatch,
      missing,
      no_recorded_hash: noRecordedHash,
    },
    chain_intact: chainIntact,
    summary,
    artifacts,
    method:
      "Each preserved file is re-read from disk and re-hashed, then compared byte-for-byte against the digest recorded at preservation time.",
    limitations:
      "This verifies internal consistency of the local evidence store. It does not provide third-party timestamping, notarisation or tamper-proof custody, and does not by itself establish legal admissibility.",
  };
}
