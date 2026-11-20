import fs from "fs";
import path from "path";

export const PROJECT_ROOT = process.cwd();
export const DATA_DIR = path.join(PROJECT_ROOT, "data");
export const DEMO_DIR = path.join(DATA_DIR, "demo");
export const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
export const EVIDENCE_DIR = path.join(DATA_DIR, "evidence");
export const FRAMES_DIR = path.join(EVIDENCE_DIR, "frames");
export const LOCALIZATION_DIR = path.join(EVIDENCE_DIR, "localization");
export const AUDIO_DIR = path.join(EVIDENCE_DIR, "audio");
export const IDENTITY_DIR = path.join(EVIDENCE_DIR, "identities");
export const SOURCES_DIR = path.join(EVIDENCE_DIR, "sources");
export const REPORTS_DIR = path.join(DATA_DIR, "reports");
export const DB_FILE = process.env.DEEPTRACE_DB_PATH || path.join(DATA_DIR, "deeptrace.db.json");

export const CONSENT_TEXT_VERSION = "1.0";
export const CONSENT_TEXT =
  "I confirm that I am the person shown in the reference material, or that I am " +
  "authorised to submit it on their behalf, and I consent to DeepTrace storing " +
  "the reference image/audio and derived biometric templates locally for the " +
  "purpose of comparing them against media I submit for investigation.";

export interface IdentityRecord {
  id: number;
  name: string;
  reference_image_path: string | null;
  reference_audio_path: string | null;
  face_signature: number[] | null;
  voice_profile: VoiceAudioProfile | null;
  face_model: string | null;
  voice_model: string | null;
  consent_given: boolean;
  consent_text_version: string;
  consent_at: string;
  created_at: string;
}

export interface SubmitterRecord {
  id: number;
  full_name: string;
  aadhaar_number: string;
  gender: "male" | "female" | "other" | "prefer_not_to_say";
  date_of_birth: string;
  phone_number: string;
  created_at: string;
}

export interface InvestigationRecord {
  id: number;
  filename: string;
  file_path: string;
  file_size_bytes: number;
  sha256_hash: string;
  perceptual_hash: string | null;
  media_type: "video" | "image" | "audio";
  status: "pending" | "analyzing" | "completed" | "failed";
  progress_stage: string | null;
  progress_percent: number;
  error_message: string | null;
  identity_id: number | null;
  submitter_id: number | null;
  duration_seconds: number | null;
  resolution: string | null;
  fps: number | null;
  frames_extracted: number;
  has_audio_stream: boolean | null;
  media_metadata: Record<string, unknown> | null;
  source_urls: string[];
  overall_risk_score: number | null;
  risk_level: string | null;
  created_at: string;
  updated_at: string;
  analysis_started_at: string | null;
  analysis_completed_at: string | null;
}

export interface EvidenceRecord {
  id: number;
  investigation_id: number;
  evidence_type: "original" | "frame" | "localization" | "audio" | "traced_copy";
  file_path: string;
  sha256_hash: string | null;
  perceptual_hash: string | null;
  timestamp_offset: number | null;
  metadata_json: Record<string, unknown> | null;
  created_at: string;
}

export interface AnalysisResultRecord {
  id: number;
  investigation_id: number;
  module_name: string;
  score: number | null;
  confidence: number | null;
  status: string;
  result_data: Record<string, unknown>;
  created_at: string;
}

export interface TraceSourceRecord {
  id: number;
  investigation_id: number;
  source_url: string | null;
  title: string | null;
  description: string | null;
  origin: "public_url" | "local_copy" | "url_reference_only";
  retrieval_status: "fetched" | "rejected" | "failed" | "not_retrieved";
  retrieval_error: string | null;
  file_path: string | null;
  content_type: string | null;
  bytes_downloaded: number | null;
  sha256_hash: string | null;
  perceptual_hash: string | null;
  similarity: number | null;
  match_type: string | null;
  similarity_label: string | null;
  details: Record<string, unknown> | null;
  discovered_at: string;
}

export interface TimelineEventRecord {
  id: number;
  investigation_id: number;
  event_type: string;
  description: string;
  created_at: string;
}

export interface VoiceAudioProfile {
  durationSeconds: number;
  sampleRate: number;
  rmsMean: number;
  rmsStd: number;
  zeroCrossingRate: number;
  clippingRatio: number;
  discontinuityScore: number;
  bandEnergies: number[];
}

export interface DatabaseState {
  counters: {
    identities: number;
    submitters: number;
    investigations: number;
    evidence: number;
    analysis_results: number;
    trace_sources: number;
    timeline_events: number;
  };
  identities: IdentityRecord[];
  submitters: SubmitterRecord[];
  investigations: InvestigationRecord[];
  evidence: EvidenceRecord[];
  analysis_results: AnalysisResultRecord[];
  trace_sources: TraceSourceRecord[];
  timeline_events: TimelineEventRecord[];
}

export function ensureRuntimeDirs(): void {
  for (const dir of [
    DATA_DIR,
    DEMO_DIR,
    UPLOAD_DIR,
    EVIDENCE_DIR,
    FRAMES_DIR,
    LOCALIZATION_DIR,
    AUDIO_DIR,
    IDENTITY_DIR,
    SOURCES_DIR,
    REPORTS_DIR,
  ]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function defaultState(): DatabaseState {
  return {
    counters: {
      identities: 0,
      submitters: 0,
      investigations: 0,
      evidence: 0,
      analysis_results: 0,
      trace_sources: 0,
      timeline_events: 0,
    },
    identities: [],
    submitters: [],
    investigations: [],
    evidence: [],
    analysis_results: [],
    trace_sources: [],
    timeline_events: [],
  };
}

let stateCache: DatabaseState | null = null;

export function readDb(): DatabaseState {
  ensureRuntimeDirs();
  if (stateCache) return stateCache;
  if (!fs.existsSync(DB_FILE)) {
    stateCache = defaultState();
    writeDb(stateCache);
    return stateCache;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, "utf-8");
    const parsed = JSON.parse(raw) as Partial<DatabaseState>;
    const base = defaultState();
    stateCache = {
      counters: { ...base.counters, ...(parsed.counters ?? {}) },
      identities: Array.isArray(parsed.identities) ? parsed.identities : [],
      submitters: Array.isArray(parsed.submitters) ? parsed.submitters : [],
      investigations: Array.isArray(parsed.investigations) ? parsed.investigations : [],
      evidence: Array.isArray(parsed.evidence) ? parsed.evidence : [],
      analysis_results: Array.isArray(parsed.analysis_results) ? parsed.analysis_results : [],
      trace_sources: Array.isArray(parsed.trace_sources) ? parsed.trace_sources : [],
      timeline_events: Array.isArray(parsed.timeline_events) ? parsed.timeline_events : [],
    };
    return stateCache;
  } catch {
    stateCache = defaultState();
    writeDb(stateCache);
    return stateCache;
  }
}

export function writeDb(state: DatabaseState): void {
  ensureRuntimeDirs();
  stateCache = state;
  const tmpFile = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(state, null, 2), "utf-8");
  fs.renameSync(tmpFile, DB_FILE);
}

export function nextId(key: keyof DatabaseState["counters"]): number {
  const db = readDb();
  db.counters[key] += 1;
  const val = db.counters[key];
  writeDb(db);
  return val;
}

export function toPublicStaticUrl(filePath: string | null): string | null {
  if (!filePath) return null;
  const resolved = path.resolve(filePath);
  const evRoot = path.resolve(EVIDENCE_DIR);
  const upRoot = path.resolve(UPLOAD_DIR);
  const demoRoot = path.resolve(DEMO_DIR);
  if (resolved.startsWith(evRoot + path.sep)) {
    return "/evidence/" + resolved.slice(evRoot.length + 1).split(path.sep).join("/");
  }
  if (resolved.startsWith(upRoot + path.sep)) {
    return "/uploads/" + resolved.slice(upRoot.length + 1).split(path.sep).join("/");
  }
  if (resolved.startsWith(demoRoot + path.sep)) {
    return "/demo-assets/" + resolved.slice(demoRoot.length + 1).split(path.sep).join("/");
  }
  return null;
}

export function repoRelative(filePath: string | null): string | null {
  if (!filePath) return null;
  const resolved = path.resolve(filePath);
  const root = path.resolve(PROJECT_ROOT);
  if (resolved.startsWith(root + path.sep)) {
    return resolved.slice(root.length + 1).split(path.sep).join("/");
  }
  return path.basename(filePath);
}

export function resolveInside(baseDir: string, candidatePath: string): string | null {
  const base = path.resolve(baseDir);
  const target = path.resolve(candidatePath);
  if (target === base || target.startsWith(base + path.sep)) {
    return target;
  }
  return null;
}

export function reportFilePath(investigationId: number): string {
  return path.join(REPORTS_DIR, `investigation_${investigationId}.pdf`);
}

export function addTimelineEvent(
  investigationId: number,
  eventType: string,
  description: string
): TimelineEventRecord {
  const db = readDb();
  db.counters.timeline_events += 1;
  const event: TimelineEventRecord = {
    id: db.counters.timeline_events,
    investigation_id: investigationId,
    event_type: eventType,
    description,
    created_at: new Date().toISOString(),
  };
  db.timeline_events.push(event);
  writeDb(db);
  return event;
}
