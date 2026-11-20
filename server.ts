import crypto from "crypto";
import express from "express";
import fs from "fs";
import multer from "multer";
import path from "path";
import { createServer as createViteServer } from "vite";
import { buildCustodyRecord, buildGuidance } from "./server/custodyAndResponse.ts";
import {
  analyzeAudioProfile,
  checkFfmpegAvailable,
  computePerceptualHash,
  computeVisualSignature,
  perceptualSimilarity,
  sha256File,
  similarityLabel,
  verifyEvidenceArtifacts,
} from "./server/forensics.ts";
import { runInvestigationPipeline } from "./server/pipeline.ts";
import { generateForensicPdfReport } from "./server/reportPdf.ts";
import {
  CONSENT_TEXT,
  CONSENT_TEXT_VERSION,
  DEMO_DIR,
  EVIDENCE_DIR,
  IDENTITY_DIR,
  PROJECT_ROOT,
  SOURCES_DIR,
  UPLOAD_DIR,
  addTimelineEvent,
  ensureRuntimeDirs,
  readDb,
  repoRelative,
  reportFilePath,
  toPublicStaticUrl,
  writeDb,
} from "./server/store.ts";
import { fetchAndComparePublicUrl, parseSourceUrls } from "./server/tracing.ts";

const MAX_UPLOAD_MB = 200;
const MAX_REFERENCE_MB = 25;
const FRAME_SAMPLES = 12;

const MEDIA_TYPES: Record<string, "video" | "image" | "audio"> = {
  ".mp4": "video",
  ".avi": "video",
  ".mov": "video",
  ".mkv": "video",
  ".webm": "video",
  ".jpg": "image",
  ".jpeg": "image",
  ".png": "image",
  ".bmp": "image",
  ".webp": "image",
  ".wav": "audio",
  ".mp3": "audio",
  ".flac": "audio",
  ".ogg": "audio",
  ".m4a": "audio",
};

function safeFilename(raw: string | undefined, fallback = "upload"): string {
  const base = path.basename((raw ?? "").replace(/\\/g, "/")).trim();
  const cleaned = base.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._-]+|[._-]+$/g, "");
  if (!cleaned) return fallback;
  const ext = path.extname(cleaned).slice(0, 12).toLowerCase();
  const stem = path.basename(cleaned, path.extname(cleaned)).slice(0, 100) || fallback;
  return `${stem}${ext}`;
}

function makeDiskUpload(targetDir: string, maxMb: number) {
  return multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => {
        ensureRuntimeDirs();
        cb(null, targetDir);
      },
      filename: (_req, file, cb) => {
        cb(null, `${crypto.randomUUID().replace(/-/g, "")}_${safeFilename(file.originalname)}`);
      },
    }),
    limits: { fileSize: maxMb * 1024 * 1024 },
  });
}

const uploadNone = multer();
const uploadSuspicious = makeDiskUpload(UPLOAD_DIR, MAX_UPLOAD_MB);
const uploadReference = makeDiskUpload(IDENTITY_DIR, MAX_REFERENCE_MB);
const uploadTraceCopy = makeDiskUpload(SOURCES_DIR, MAX_REFERENCE_MB);

function serializeInvestigationDetail(investigationId: number) {
  const db = readDb();
  const inv = db.investigations.find((i) => i.id === investigationId);
  if (!inv) return null;

  const identity = inv.identity_id
    ? db.identities.find((id) => id.id === inv.identity_id) ?? null
    : null;
  const submitter = inv.submitter_id
    ? db.submitters.find((s) => s.id === inv.submitter_id) ?? null
    : null;
  const analyses = db.analysis_results.filter((a) => a.investigation_id === inv.id);
  const evidence = db.evidence.filter((e) => e.investigation_id === inv.id);
  const traceSources = db.trace_sources.filter((s) => s.investigation_id === inv.id);

  const analysisMap: Record<
    string,
    {
      score: number | null;
      confidence: number | null;
      status: string;
      data: Record<string, unknown>;
      created_at: string;
    }
  > = {};
  for (const row of analyses) {
    analysisMap[row.module_name] = {
      score: row.score,
      confidence: row.confidence,
      status: row.status,
      data: row.result_data,
      created_at: row.created_at,
    };
  }

  return {
    id: inv.id,
    filename: inv.filename,
    media_type: inv.media_type,
    file_size_bytes: inv.file_size_bytes,
    sha256_hash: inv.sha256_hash,
    perceptual_hash: inv.perceptual_hash,
    status: inv.status,
    progress_stage: inv.progress_stage,
    progress_percent: inv.progress_percent,
    error_message: inv.error_message,
    identity_id: inv.identity_id,
    identity_name: identity?.name ?? null,
    submitter: submitter
      ? {
          id: submitter.id,
          full_name: submitter.full_name,
          masked_aadhaar: `XXXX XXXX ${submitter.aadhaar_number.slice(-4)}`,
          masked_phone: `+91 ••••••${submitter.phone_number.slice(-4)}`,
          gender: submitter.gender,
        }
      : null,
    duration_seconds: inv.duration_seconds,
    resolution: inv.resolution,
    fps: inv.fps,
    frames_extracted: inv.frames_extracted,
    has_audio_stream: inv.has_audio_stream,
    media_metadata: inv.media_metadata,
    source_urls: inv.source_urls,
    overall_risk_score: inv.overall_risk_score,
    risk_level: inv.risk_level,
    created_at: inv.created_at,
    analysis_started_at: inv.analysis_started_at,
    analysis_completed_at: inv.analysis_completed_at,
    report_available: fs.existsSync(reportFilePath(inv.id)),
    analysis_results: analysisMap,
    evidence: evidence.map((e) => ({
      id: e.id,
      type: e.evidence_type,
      file_path: repoRelative(e.file_path),
      url: toPublicStaticUrl(e.file_path),
      filename: path.basename(e.file_path),
      sha256: e.sha256_hash,
      perceptual_hash: e.perceptual_hash,
      timestamp_offset: e.timestamp_offset,
      metadata: e.metadata_json,
      created_at: e.created_at,
    })),
    trace_sources: traceSources.map((s) => ({
      id: s.id,
      source_url: s.source_url,
      title: s.title,
      description: s.description,
      origin: s.origin,
      retrieval_status: s.retrieval_status,
      retrieval_error: s.retrieval_error,
      file_path: repoRelative(s.file_path),
      url: toPublicStaticUrl(s.file_path),
      content_type: s.content_type,
      bytes_downloaded: s.bytes_downloaded,
      sha256: s.sha256_hash,
      perceptual_hash: s.perceptual_hash,
      similarity: s.similarity,
      match_type: s.match_type,
      similarity_label: s.similarity_label,
      details: s.details,
      discovered_at: s.discovered_at,
    })),
  };
}

async function startServer() {
  ensureRuntimeDirs();
  readDb();

  const app = express();
  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ extended: true }));

  app.use("/evidence", express.static(EVIDENCE_DIR));
  app.use("/uploads", express.static(UPLOAD_DIR));
  if (fs.existsSync(DEMO_DIR)) {
    app.use("/demo-assets", express.static(DEMO_DIR));
  }

  // ─── Health & Metadata ──────────────────────────────────────────────────
  app.get("/api/health", async (_req, res) => {
    const ffmpeg = await checkFfmpegAvailable();
    res.json({
      status: "ok",
      service: "DeepTrace API",
      version: "1.0.0",
      capabilities: {
        ffmpeg: ffmpeg.available,
        deepfake_detector: true,
        face_identity: true,
        voice_comparison: true,
        pdf_reports: true,
      },
      limits: {
        max_upload_mb: MAX_UPLOAD_MB,
        max_reference_mb: MAX_REFERENCE_MB,
        frame_samples: FRAME_SAMPLES,
      },
      note: "Running Node.js + FFmpeg forensic engine inside AI Studio.",
    });
  });

  app.get("/api/consent-text", (_req, res) => {
    res.json({ version: CONSENT_TEXT_VERSION, text: CONSENT_TEXT });
  });

  app.get("/api/dashboard/stats", (_req, res) => {
    const db = readDb();
    res.json({
      active_investigations: db.investigations.length,
      evidence_items: db.evidence.length,
      protected_identities: db.identities.length,
      high_risk_findings: db.investigations.filter(
        (i) => i.risk_level === "HIGH" || i.risk_level === "CRITICAL"
      ).length,
    });
  });

  app.get("/api/demo/assets", (_req, res) => {
    if (!fs.existsSync(DEMO_DIR)) {
      return res.json({ available: false, count: 0, assets: [], note: "No demo directory present." });
    }
    const files = fs.readdirSync(DEMO_DIR).sort();
    const assets = files
      .map((filename) => {
        const ext = path.extname(filename).toLowerCase();
        const media_type = MEDIA_TYPES[ext];
        if (!media_type) return null;
        const full = path.join(DEMO_DIR, filename);
        const stat = fs.statSync(full);
        return {
          filename,
          media_type,
          size_bytes: stat.size,
          url: `/demo-assets/${encodeURIComponent(filename)}`,
        };
      })
      .filter(Boolean);
    res.json({
      available: assets.length > 0,
      count: assets.length,
      assets,
      note: "Bundled repository demo inputs.",
    });
  });

  // ─── Submitter & Identity Enrollment ────────────────────────────────────
  app.post("/api/submitter", uploadNone.none(), (req, res) => {
    const fullName = String(req.body?.full_name ?? "").trim();
    const aadhaar = String(req.body?.aadhaar_number ?? "").replace(/\D/g, "");
    const gender = String(req.body?.gender ?? "").trim().toLowerCase();
    const dob = String(req.body?.date_of_birth ?? "").trim();
    const phone = String(req.body?.phone_number ?? "").replace(/\D/g, "");

    if (fullName.length < 2 || fullName.length > 120) {
      return res.status(422).json({ detail: "Enter a valid full name (2–120 characters)." });
    }
    if (aadhaar.length !== 12) {
      return res.status(422).json({ detail: "Aadhaar number must be exactly 12 digits." });
    }
    if (!["male", "female", "other", "prefer_not_to_say"].includes(gender)) {
      return res.status(422).json({ detail: "Select a valid gender option." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dob) || Number.isNaN(Date.parse(dob)) || new Date(dob) > new Date()) {
      return res.status(422).json({ detail: "Enter a valid past date of birth (YYYY-MM-DD)." });
    }
    if (phone.length !== 10 || !/^[6-9]/.test(phone)) {
      return res.status(422).json({ detail: "Enter a valid 10-digit Indian mobile number." });
    }

    const db = readDb();
    db.counters.submitters += 1;
    const id = db.counters.submitters;
    db.submitters.push({
      id,
      full_name: fullName,
      aadhaar_number: aadhaar,
      gender: gender as "male" | "female" | "other" | "prefer_not_to_say",
      date_of_birth: dob,
      phone_number: phone,
      created_at: new Date().toISOString(),
    });
    writeDb(db);

    res.status(201).json({
      id,
      full_name: fullName,
      message: "Identification record stored locally (self-declared; not verified against UIDAI).",
    });
  });

  app.get("/api/identities", (_req, res) => {
    const db = readDb();
    res.json(
      db.identities.map((id) => ({
        id: id.id,
        name: id.name,
        face_enrolled: Boolean(id.face_signature),
        voice_enrolled: Boolean(id.voice_profile),
        consent_given: id.consent_given,
        consent_at: id.consent_at,
        consent_version: id.consent_text_version,
        face_model: id.face_model,
        face_embedding_dimensions: id.face_signature?.length ?? null,
        reference_image_path: toPublicStaticUrl(id.reference_image_path),
        created_at: id.created_at,
      }))
    );
  });

  app.post(
    "/api/identity/enroll",
    uploadReference.fields([
      { name: "reference_image", maxCount: 1 },
      { name: "reference_audio", maxCount: 1 },
    ]),
    async (req, res) => {
      const files = req.files as Record<string, Express.Multer.File[]> | undefined;
      const imgFile = files?.reference_image?.[0];
      const audFile = files?.reference_audio?.[0];

      const name = String(req.body?.name ?? "").trim();
      const consentRaw = String(req.body?.consent_given ?? "").trim().toLowerCase();
      const consentGiven =
        consentRaw === "true" || consentRaw === "1" || consentRaw === "yes" || consentRaw === "on";

      if (!consentGiven) {
        if (imgFile && fs.existsSync(imgFile.path)) fs.unlinkSync(imgFile.path);
        if (audFile && fs.existsSync(audFile.path)) fs.unlinkSync(audFile.path);
        return res.status(422).json({
          detail: "Explicit consent is required before storing reference biometrics.",
        });
      }
      if (name.length < 2) {
        if (imgFile && fs.existsSync(imgFile.path)) fs.unlinkSync(imgFile.path);
        if (audFile && fs.existsSync(audFile.path)) fs.unlinkSync(audFile.path);
        return res.status(422).json({ detail: "Reference identity name must be at least 2 characters." });
      }
      if (!imgFile) {
        if (audFile && fs.existsSync(audFile.path)) fs.unlinkSync(audFile.path);
        return res.status(422).json({ detail: "A reference photo is required." });
      }

      const faceSig = await computeVisualSignature(imgFile.path);
      const voiceProf = audFile ? await analyzeAudioProfile(audFile.path) : null;

      const db = readDb();
      db.counters.identities += 1;
      const now = new Date().toISOString();
      const rec = {
        id: db.counters.identities,
        name,
        reference_image_path: imgFile.path,
        reference_audio_path: audFile?.path ?? null,
        face_signature: faceSig,
        voice_profile: voiceProf,
        face_model: faceSig ? "Spatial-chroma 64-d normalized visual descriptor" : null,
        voice_model: voiceProf ? "16kHz PCM temporal envelope profile" : null,
        consent_given: true,
        consent_text_version: CONSENT_TEXT_VERSION,
        consent_at: now,
        created_at: now,
      };
      db.identities.push(rec);
      writeDb(db);

      res.status(201).json({
        id: rec.id,
        name: rec.name,
        face_enrolled: Boolean(rec.face_signature),
        voice_enrolled: Boolean(rec.voice_profile),
        consent_given: true,
        consent_at: rec.consent_at,
        consent_version: rec.consent_text_version,
        face_model: rec.face_model,
        face_embedding_dimensions: rec.face_signature?.length ?? null,
        reference_image_path: toPublicStaticUrl(rec.reference_image_path),
        created_at: rec.created_at,
      });
    }
  );

  // ─── Investigations ─────────────────────────────────────────────────────
  app.post("/api/investigate", uploadSuspicious.single("file"), async (req, res) => {
    const file = req.file;
    if (!file) {
      return res.status(422).json({ detail: "No suspicious media file was uploaded." });
    }

    const ext = path.extname(file.originalname).toLowerCase();
    const mediaType = MEDIA_TYPES[ext];
    if (!mediaType) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(415).json({
        detail: `Unsupported media extension (${ext || "unknown"}).`,
      });
    }

    const submitterIdRaw = req.body?.submitter_id;
    const submitterId = submitterIdRaw ? Number(submitterIdRaw) : null;
    const identityIdRaw = req.body?.identity_id;
    const identityId = identityIdRaw ? Number(identityIdRaw) : null;

    const db = readDb();
    if (!submitterId || !db.submitters.some((s) => s.id === submitterId)) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(422).json({ detail: "Valid submitter_id from identification intake is required." });
    }
    if (identityId !== null && !db.identities.some((id) => id.id === identityId)) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(422).json({ detail: "Referenced identity_id was not found." });
    }

    const sha256 = sha256File(file.path);
    const pHash = mediaType !== "audio" ? await computePerceptualHash(file.path) : null;
    const sourceUrls = parseSourceUrls(req.body?.source_urls);
    const now = new Date().toISOString();

    db.counters.investigations += 1;
    const invId = db.counters.investigations;
    db.investigations.push({
      id: invId,
      filename: safeFilename(file.originalname),
      file_path: file.path,
      file_size_bytes: file.size,
      sha256_hash: sha256,
      perceptual_hash: pHash,
      media_type: mediaType,
      status: "pending",
      progress_stage: "intake",
      progress_percent: 0,
      error_message: null,
      identity_id: identityId,
      submitter_id: submitterId,
      duration_seconds: null,
      resolution: null,
      fps: null,
      frames_extracted: 0,
      has_audio_stream: null,
      media_metadata: null,
      source_urls: sourceUrls,
      overall_risk_score: null,
      risk_level: null,
      created_at: now,
      updated_at: now,
      analysis_started_at: null,
      analysis_completed_at: null,
    });

    db.counters.evidence += 1;
    db.evidence.push({
      id: db.counters.evidence,
      investigation_id: invId,
      evidence_type: "original",
      file_path: file.path,
      sha256_hash: sha256,
      perceptual_hash: pHash,
      timestamp_offset: null,
      metadata_json: { original_filename: safeFilename(file.originalname) },
      created_at: now,
    });
    writeDb(db);

    addTimelineEvent(
      invId,
      "evidence_preserved",
      `Preserved original ${mediaType} (${file.size} bytes) with SHA-256 ${sha256.slice(0, 12)}….`
    );

    res.status(201).json({
      id: invId,
      status: "pending",
      media_type: mediaType,
      sha256,
    });
  });

  app.get("/api/investigations", (_req, res) => {
    const db = readDb();
    const list = [...db.investigations]
      .sort((a, b) => b.id - a.id)
      .map((inv) => ({
        id: inv.id,
        filename: inv.filename,
        media_type: inv.media_type,
        status: inv.status,
        risk_level: inv.risk_level,
        created_at: inv.created_at,
        identity_id: inv.identity_id,
        submitter_id: inv.submitter_id,
        overall_risk_score: inv.overall_risk_score,
      }));
    res.json(list);
  });

  app.get("/api/investigation/:id", (req, res) => {
    const id = Number(req.params.id);
    const detail = serializeInvestigationDetail(id);
    if (!detail) return res.status(404).json({ detail: "Investigation not found." });
    res.json(detail);
  });

  app.post("/api/investigation/:id/analyze", (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    const inv = db.investigations.find((i) => i.id === id);
    if (!inv) return res.status(404).json({ detail: "Investigation not found." });
    if (inv.status === "analyzing") {
      return res.json({ status: "analyzing", message: "Analysis is already running." });
    }
    const pdf = reportFilePath(id);
    if (fs.existsSync(pdf)) fs.unlinkSync(pdf);

    inv.status = "analyzing";
    inv.progress_stage = "queued";
    inv.progress_percent = 5;
    writeDb(db);

    void runInvestigationPipeline(id);
    res.json({ status: "analyzing", investigation_id: id });
  });

  app.get("/api/investigation/:id/timeline", (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    if (!db.investigations.some((i) => i.id === id)) {
      return res.status(404).json({ detail: "Investigation not found." });
    }
    res.json(db.timeline_events.filter((e) => e.investigation_id === id));
  });

  app.get("/api/investigation/:id/evidence", (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    if (!db.investigations.some((i) => i.id === id)) {
      return res.status(404).json({ detail: "Investigation not found." });
    }
    res.json(
      db.evidence
        .filter((e) => e.investigation_id === id)
        .map((e) => ({
          id: e.id,
          type: e.evidence_type,
          file_path: repoRelative(e.file_path),
          url: toPublicStaticUrl(e.file_path),
          filename: path.basename(e.file_path),
          sha256: e.sha256_hash,
          perceptual_hash: e.perceptual_hash,
          timestamp_offset: e.timestamp_offset,
          metadata: e.metadata_json,
          created_at: e.created_at,
        }))
    );
  });

  app.get("/api/investigation/:id/verify", (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    if (!db.investigations.some((i) => i.id === id)) {
      return res.status(404).json({ detail: "Investigation not found." });
    }
    const rows = db.evidence.filter((e) => e.investigation_id === id);
    const report = verifyEvidenceArtifacts(rows, id);
    addTimelineEvent(id, "integrity_verified", report.summary);
    res.json(report);
  });

  app.get("/api/investigation/:id/custody", (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    const inv = db.investigations.find((i) => i.id === id);
    if (!inv) return res.status(404).json({ detail: "Investigation not found." });
    const rows = db.evidence.filter((e) => e.investigation_id === id);
    const timeline = db.timeline_events.filter((e) => e.investigation_id === id);
    const verification = verifyEvidenceArtifacts(rows, id);
    const identity = inv.identity_id
      ? db.identities.find((x) => x.id === inv.identity_id) ?? null
      : null;
    res.json(buildCustodyRecord({ investigation: inv, evidence: rows, timeline, verification, identity }));
  });

  app.get("/api/investigation/:id/trace", (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    if (!db.investigations.some((i) => i.id === id)) {
      return res.status(404).json({ detail: "Investigation not found." });
    }
    const sources = db.trace_sources
      .filter((s) => s.investigation_id === id)
      .map((s) => ({
        id: s.id,
        source_url: s.source_url,
        title: s.title,
        description: s.description,
        origin: s.origin,
        retrieval_status: s.retrieval_status,
        retrieval_error: s.retrieval_error,
        file_path: repoRelative(s.file_path),
        url: toPublicStaticUrl(s.file_path),
        content_type: s.content_type,
        bytes_downloaded: s.bytes_downloaded,
        sha256: s.sha256_hash,
        perceptual_hash: s.perceptual_hash,
        similarity: s.similarity,
        match_type: s.match_type,
        similarity_label: s.similarity_label,
        details: s.details,
        discovered_at: s.discovered_at,
      }));
    res.json({
      investigation_id: id,
      source_count: sources.length,
      retrieved_count: sources.filter((s) => s.retrieval_status === "fetched").length,
      scope:
        "DeepTrace retrieves only the public HTTPS URLs you supply here under SSRF containment. It does not perform internet-wide surveillance or access private accounts.",
      sources,
    });
  });

  app.post("/api/investigation/:id/trace", uploadTraceCopy.single("local_copy"), async (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    const inv = db.investigations.find((i) => i.id === id);
    if (!inv) return res.status(404).json({ detail: "Investigation not found." });

    const urls = parseSourceUrls(req.body?.source_urls ?? req.body?.urls);
    const localFile = req.file;
    const label = String(req.body?.label ?? "").trim();

    if (urls.length === 0 && !localFile) {
      return res.status(422).json({ detail: "Supply at least one public HTTPS URL or a local copy file." });
    }

    const created = [];

    if (localFile) {
      const sha = sha256File(localFile.path);
      const pHash = await computePerceptualHash(localFile.path);
      let sim: number | null = null;
      let matchType: string | null = null;
      if (sha === inv.sha256_hash) {
        sim = 1.0;
        matchType = "exact";
      } else {
        sim = perceptualSimilarity(inv.perceptual_hash, pHash);
        if (sim !== null) {
          matchType = sim >= 0.78 ? "near" : "none";
        }
      }
      const dbCur = readDb();
      dbCur.counters.trace_sources += 1;
      const rec = {
        id: dbCur.counters.trace_sources,
        investigation_id: id,
        source_url: null,
        title: label || "Local copy supplied by investigator",
        description: null,
        origin: "local_copy" as const,
        retrieval_status: "fetched" as const,
        retrieval_error: null,
        file_path: localFile.path,
        content_type: localFile.mimetype,
        bytes_downloaded: localFile.size,
        sha256_hash: sha,
        perceptual_hash: pHash,
        similarity: sim,
        match_type: matchType,
        similarity_label: similarityLabel(sim),
        details: null,
        discovered_at: new Date().toISOString(),
      };
      dbCur.trace_sources.push(rec);
      dbCur.counters.evidence += 1;
      dbCur.evidence.push({
        id: dbCur.counters.evidence,
        investigation_id: id,
        evidence_type: "traced_copy",
        file_path: localFile.path,
        sha256_hash: sha,
        perceptual_hash: pHash,
        timestamp_offset: null,
        metadata_json: { label: rec.title },
        created_at: new Date().toISOString(),
      });
      writeDb(dbCur);
      created.push({
        ...rec,
        sha256: rec.sha256_hash,
        file_path: repoRelative(rec.file_path),
        url: toPublicStaticUrl(rec.file_path),
      });
    }

    for (const rawUrl of urls) {
      const traced = await fetchAndComparePublicUrl({
        investigationId: id,
        rawUrl,
        originalSha256: inv.sha256_hash,
        originalPerceptualHash: inv.perceptual_hash,
      });
      const dbCur = readDb();
      dbCur.counters.trace_sources += 1;
      const rec = {
        id: dbCur.counters.trace_sources,
        investigation_id: id,
        source_url: traced.source_url,
        title: null,
        description: null,
        origin: traced.origin,
        retrieval_status: traced.retrieval_status,
        retrieval_error: traced.retrieval_error,
        file_path: traced.file_path,
        content_type: traced.content_type,
        bytes_downloaded: traced.bytes_downloaded,
        sha256_hash: traced.sha256_hash,
        perceptual_hash: traced.perceptual_hash,
        similarity: traced.similarity,
        match_type: traced.match_type,
        similarity_label: traced.similarity_label,
        details: null,
        discovered_at: new Date().toISOString(),
      };
      dbCur.trace_sources.push(rec);
      if (traced.file_path && traced.sha256_hash) {
        dbCur.counters.evidence += 1;
        dbCur.evidence.push({
          id: dbCur.counters.evidence,
          investigation_id: id,
          evidence_type: "traced_copy",
          file_path: traced.file_path,
          sha256_hash: traced.sha256_hash,
          perceptual_hash: traced.perceptual_hash,
          timestamp_offset: null,
          metadata_json: { source_url: traced.source_url },
          created_at: new Date().toISOString(),
        });
      }
      writeDb(dbCur);
      created.push({
        ...rec,
        sha256: rec.sha256_hash,
        file_path: repoRelative(rec.file_path),
        url: toPublicStaticUrl(rec.file_path),
      });
    }

    addTimelineEvent(id, "trace_executed", `Processed ${created.length} traced source(s).`);
    res.json({ investigation_id: id, processed: created.length, sources: created });
  });

  app.get("/api/investigation/:id/response-guidance", (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    const inv = db.investigations.find((i) => i.id === id);
    if (!inv) return res.status(404).json({ detail: "Investigation not found." });
    const identity = inv.identity_id ? db.identities.find((x) => x.id === inv.identity_id) ?? null : null;
    const analyses = db.analysis_results.filter((a) => a.investigation_id === id);
    const modules: Record<string, { status: string; score: number | null; result_data: Record<string, unknown> } | undefined> = {};
    for (const row of analyses) {
      modules[row.module_name] = { status: row.status, score: row.score, result_data: row.result_data };
    }
    const traceSources = db.trace_sources.filter((s) => s.investigation_id === id);
    res.json(
      buildGuidance({
        investigation: inv,
        identityName: identity?.name ?? null,
        modules,
        traceSources,
      })
    );
  });

  app.get("/api/investigation/:id/report", async (req, res) => {
    const id = Number(req.params.id);
    const db = readDb();
    const inv = db.investigations.find((i) => i.id === id);
    if (!inv) return res.status(404).json({ detail: "Investigation not found." });

    const submitter = inv.submitter_id ? db.submitters.find((s) => s.id === inv.submitter_id) ?? null : null;
    const identity = inv.identity_id ? db.identities.find((x) => x.id === inv.identity_id) ?? null : null;
    const analyses = db.analysis_results.filter((a) => a.investigation_id === id);
    const evidence = db.evidence.filter((e) => e.investigation_id === id);
    const timeline = db.timeline_events.filter((e) => e.investigation_id === id);
    const traceSources = db.trace_sources.filter((s) => s.investigation_id === id);
    const verification = verifyEvidenceArtifacts(evidence, id);

    const pdf = await generateForensicPdfReport({
      investigation: inv,
      submitter,
      identity,
      analyses,
      evidence,
      timeline,
      traceSources,
      verification,
    });

    addTimelineEvent(
      id,
      "report_generated",
      `Forensic incident report generated (SHA-256 ${pdf.sha256.slice(0, 16)}…).`
    );
    res.json({
      status: "generated",
      report_path: repoRelative(pdf.filePath),
      filename: path.basename(pdf.filePath),
      sha256: pdf.sha256,
      download_url: `/api/report/${id}/download`,
    });
  });

  app.get("/api/report/:id/download", (req, res) => {
    const id = Number(req.params.id);
    const pdf = reportFilePath(id);
    if (!fs.existsSync(pdf)) {
      return res.status(404).json({ detail: "Report not found. Generate it first." });
    }
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="investigation_${id}.pdf"`);
    res.sendFile(pdf);
  });

  app.get("/api/benchmark", (_req, res) => {
    res.json({
      available: false,
      metrics_available: false,
      robustness_available: false,
      boundary:
        "Labelled metrics say how often the detector is right on a dataset. Robustness says how much its score moves when the same file is degraded. Neither is a claim about a specific case.",
      reason:
        "No PyTorch benchmark corpus has been executed inside this Node.js runtime. DeepTrace never fabricates pre-computed metrics.",
      robustness: {
        available: false,
        reason: "No robustness evaluation run has been stored in this runtime.",
      },
      harness: {
        metrics_command: "backend/venv/Scripts/python.exe scripts/benchmark.py",
        robustness_command: "backend/venv/Scripts/python.exe scripts/robustness.py",
        fetch_command: "backend/venv/Scripts/python.exe scripts/fetch_eval_data.py",
        interpreter_note:
          "Run from the Python repository root with the backend virtual environment interpreter so PyTorch detectors rather than heuristic fallbacks are measured.",
      },
    });
  });

  app.use((err: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err && typeof err === "object" && "code" in err && (err as { code?: string }).code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ detail: "Uploaded file exceeds the size limit." });
    }
    next(err);
  });

  const isProd = process.env.NODE_ENV === "production";
  if (isProd) {
    const distDir = path.join(PROJECT_ROOT, "dist");
    app.use(express.static(distDir));
    app.get("/{*path}", (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  const port = Number(process.env.PORT || 3000);
  app.listen(port, "0.0.0.0", () => {
    console.log(`DeepTrace full-stack server listening on http://0.0.0.0:${port}`);
  });
}

void startServer();
