import path from "path";
import {
  repoRelative,
  toPublicStaticUrl,
  type EvidenceRecord,
  type IdentityRecord,
  type InvestigationRecord,
  type TimelineEventRecord,
  type TraceSourceRecord,
} from "./store.ts";

export const HASH_ALGORITHM = "SHA-256";

export const CUSTODY_SCOPE = {
  definition:
    "A complete chain of custody records four things about an item of evidence: what it is, who held it, when it passed from one holder to the next, and under what authority.",
  deeptrace_supplies: [
    "What the item is — the exact bytes received, identified by a digest computed as they were written to disk.",
    "What was produced from it — every frame, audio track and overlay the pipeline derived, each with its own digest.",
    "When each of those things was recorded, in sequence, by this machine's clock.",
    "Whether the preserved files still match the digests recorded for them.",
  ],
  investigator_supplies: [
    "Who held the media before it was submitted to DeepTrace, and how they obtained it.",
    "Who operated DeepTrace, on what authority, and who has had access to this machine.",
    "Every hand-off of the exported report and evidence package after it leaves DeepTrace.",
    "Any external timestamping, sealing or notarisation the case requires.",
  ],
  statement:
    "DeepTrace evidences the file half of the chain and records no custodian, so this is a file-integrity record rather than a complete chain of custody. The investigating officer supplies the custodial half from their own case notes; the two together form the chain.",
};

export const HASHING_PROVES = [
  {
    claim: "The exact bytes DeepTrace received",
    detail:
      "The digest is computed while the upload is being written to disk, over the same byte stream that lands in the evidence store. Client-submitted hashes are never accepted.",
  },
  {
    claim: "Change to a preserved file is detectable, as long as the record is untouched",
    detail:
      "Re-reading a file and re-hashing it reproduces the recorded digest exactly if nothing changed, and altering a single bit produces an entirely different digest.",
  },
  {
    claim: "Two files are, or are not, the same file",
    detail:
      "Identical digests mean identical bytes. This links the submitted media to the report and to any traced copy that is byte-identical.",
  },
  {
    claim: "Which exact file each finding refers to",
    detail:
      "Every analysis result is attached to a case whose original file has a recorded digest.",
  },
];

export const HASHING_DOES_NOT_PROVE = [
  {
    claim: "Not who created, uploaded or handled the file",
    detail:
      "DeepTrace records no operator or session identity. It runs as a single-operator local tool, so the record describes what happened to the file, never who did it.",
  },
  {
    claim: "Not when the content was originally made",
    detail:
      "The recorded time is when DeepTrace received the file, taken from this machine's clock, with no external RFC 3161 timestamp authority.",
  },
  {
    claim: "Not whether the content is authentic or manipulated",
    detail:
      "A hash is indifferent to what a file depicts. A fabricated video hashes just as cleanly as a genuine one.",
  },
  {
    claim: "Not tamper-proof, and not fully tamper-evident either",
    detail:
      "The digest sits in the same writable local store as the file it describes. Changing a file alone is detected; changing both file and record together is not.",
  },
  {
    claim: "Nothing about the file before DeepTrace received it",
    detail:
      "The digest begins when bytes enter DeepTrace's write loop and says nothing about prior edits or re-encoding.",
  },
  {
    claim: "Not legal admissibility",
    detail:
      "Admissibility is decided by a court under the applicable rules of evidence on the complete record.",
  },
];

export const AI_ESTABLISHES = [
  {
    claim: "A signal indicator of manipulation, not a verdict",
    detail:
      "The visual detector returns a score for each sampled frame, and the case score is a weighted fusion of only the signals that actually ran.",
  },
  {
    claim: "Similarity to an enrolled reference, not identity",
    detail:
      "Visual and audio comparisons measure distances between descriptors; high similarity is consistent with the reference without asserting identity.",
  },
  {
    claim: "Indicators measured over a sample",
    detail:
      "Video is analysed on sampled frames rather than every frame, and audio on the extracted track.",
  },
  {
    claim: "Results that are reproducible, and deliberately not preserved",
    detail:
      "Analysis output is derived data that can be recomputed from the preserved original at any time.",
  },
];

export const AI_DOES_NOT_ESTABLISH = [
  {
    claim: "Not who made the media, or with which tool",
    detail: "No module attributes content to a creator, account, device, or generation tool.",
  },
  {
    claim: "Not intent, and not a criminal offence",
    detail: "A score describes signal in a file; intent and unlawfulness are for an investigator and court.",
  },
  {
    claim: "Not a guarantee in either direction",
    detail: "Compression, re-uploading, and screen recording degrade the signal detectors rely on.",
  },
  {
    claim: "Not authority over the preserved evidence",
    detail: "Re-running analysis can update scores; it never modifies the preserved original bytes or digest.",
  },
];

export const REPORTING_ROUTES = [
  {
    route: "National Cyber Crime Reporting Portal",
    detail:
      "cybercrime.gov.in — the Government of India portal for reporting cybercrime, including a dedicated category for obscene or impersonating content.",
    who_acts: "The affected person or their authorised representative files the complaint.",
  },
  {
    route: "Cyber Crime Helpline 1930",
    detail: "National helpline for cyber-financial and cybercrime assistance.",
    who_acts: "The affected person calls; DeepTrace cannot place the call.",
  },
  {
    route: "Local police / cyber cell",
    detail:
      "An FIR or written complaint at the jurisdictional police station or cyber cell, with the exported report and preserved media attached.",
    who_acts: "The affected person or investigating officer.",
  },
  {
    route: "Platform trust & safety / grievance officer",
    detail:
      "Most platforms operating in India publish a grievance officer contact and an impersonation or synthetic-media reporting form.",
    who_acts: "The affected person submits the platform's own report form.",
  },
];

const ROLE_LABELS: Record<string, string> = {
  original: "Submitted media — exact upload preserved at intake",
  frame: "Sampled video frame derived by FFmpeg",
  localization: "High-frequency residual overlay derived from frame",
  audio: "16 kHz mono WAV track demuxed from media",
  traced_copy: "External copy retrieved from public URL or investigator",
};

export function buildCustodyRecord(params: {
  investigation: InvestigationRecord;
  evidence: EvidenceRecord[];
  timeline: TimelineEventRecord[];
  verification: ReturnType<typeof import("./forensics.ts").verifyEvidenceArtifacts>;
  identity: IdentityRecord | null;
}) {
  const { investigation, evidence, timeline, verification, identity } = params;
  const original = evidence.find((e) => e.evidence_type === "original");

  const ledger = evidence.map((item) => ({
    evidence_id: item.id,
    evidence_type: item.evidence_type,
    origin: item.evidence_type === "original" || item.evidence_type === "traced_copy" ? "acquired" : "derived",
    role: ROLE_LABELS[item.evidence_type] ?? item.evidence_type,
    filename: path.basename(item.file_path),
    public_path: toPublicStaticUrl(item.file_path) ?? repoRelative(item.file_path),
    sha256: item.sha256_hash,
    perceptual_hash: item.perceptual_hash,
    digest_recorded: Boolean(item.sha256_hash),
    timestamp_offset: item.timestamp_offset,
    recorded_at: item.created_at,
  }));

  const acquired = ledger.filter((l) => l.origin === "acquired");
  const derived = ledger.filter((l) => l.origin === "derived");
  const undigested = ledger.filter((l) => !l.digest_recorded);

  const gaps = [
    {
      gap: "No identified custodian",
      detail:
        "No table records an operator, account, or session. DeepTrace covers the handling of files, while the investigator supplies the custodial half from case notes.",
    },
    {
      gap: "No third-party timestamping",
      detail:
        "Times come from the local system clock without an RFC 3161 timestamp authority or notarisation.",
    },
    {
      gap: "Verification cannot detect a change made to both file and record",
      detail:
        "The recorded digest lives in the same writable local store as the evidence files.",
    },
    {
      gap: "Evidence files are served without authentication",
      detail:
        "Preserved artifacts are served locally over static routes; intended for single-operator local environments.",
    },
  ];
  if (identity) {
    gaps.push({
      gap: "Reference media is stored without an evidence digest",
      detail:
        "Enrolled reference photos and voice clips are stored with recorded consent, while integrity verification covers case evidence artifacts.",
    });
  }

  return {
    investigation_id: investigation.id,
    custody_scope: CUSTODY_SCOPE,
    acquisition: {
      investigation_id: investigation.id,
      filename: investigation.filename,
      file_size: investigation.file_size_bytes,
      media_type: investigation.media_type,
      sha256: original?.sha256_hash ?? investigation.sha256_hash,
      perceptual_hash: investigation.perceptual_hash,
      recorded_at: investigation.created_at,
      public_path: toPublicStaticUrl(investigation.file_path),
    },
    derivation_note:
      "Derived artifacts (sampled frames, extracted audio, and residual overlays) are recomputed deterministically from the preserved original and hashed at creation.",
    artifact_ledger: ledger,
    counts: {
      artifacts: ledger.length,
      acquired: acquired.length,
      derived: derived.length,
      without_digest: undigested.length,
    },
    chronology: timeline.map((ev, index) => ({
      seq: index + 1,
      id: ev.id,
      event_type: ev.event_type,
      description: ev.description,
      created_at: ev.created_at,
    })),
    chronology_note:
      "Case events are written in sequence as stages execute. Viewing this custody record does not append an event; running integrity verification does.",
    integrity_check: {
      verified_at: verification.verified_at,
      algorithm: verification.algorithm,
      artifacts_checked: verification.artifacts_checked,
      chain_intact: verification.chain_intact,
      summary: verification.summary,
      counts: verification.counts,
      method: verification.method,
      limitations: verification.limitations,
    },
    hashing_proves: HASHING_PROVES,
    hashing_does_not_prove: HASHING_DOES_NOT_PROVE,
    ai_establishes: AI_ESTABLISHES,
    ai_does_not_establish: AI_DOES_NOT_ESTABLISH,
    custody_gaps: gaps,
    boundary_summary:
      "SHA-256 hashing establishes that the preserved files have not changed since DeepTrace received them. Forensic analysis estimates indicators of manipulation and similarity. Neither answers the other's question.",
  };
}

export function buildGuidance(params: {
  investigation: InvestigationRecord;
  identityName: string | null;
  modules: Record<string, { status: string; score: number | null; result_data: Record<string, unknown> } | undefined>;
  traceSources: TraceSourceRecord[];
}) {
  const { investigation, identityName, modules, traceSources } = params;
  const riskLevel = investigation.risk_level ?? "LOW";
  const priorityMap: Record<string, string> = {
    CRITICAL: "Immediate",
    HIGH: "Urgent",
    MEDIUM: "Standard",
    LOW: "Routine",
  };
  const priority = priorityMap[riskLevel] ?? "Standard";

  const deepfake = modules.deepfake;
  const identity = modules.identity;
  const voice = modules.voice;
  const propagation = modules.similarity;
  const localization = modules.localization;

  const intervals = Array.isArray(localization?.result_data?.suspicious_intervals)
    ? (localization?.result_data?.suspicious_intervals as Array<{ label?: string; start_seconds?: number }>)
    : [];

  const caseFindings: string[] = [];
  if (deepfake?.score !== null && deepfake?.score !== undefined) {
    caseFindings.push(
      `Visual manipulation indicator scored ${Number(deepfake.score).toFixed(2)} (${String(deepfake.result_data.model_name ?? "residual analyzer")}).`
    );
  }
  if (identity?.result_data?.best_similarity !== undefined && identity?.result_data?.best_similarity !== null) {
    caseFindings.push(
      `Visual similarity to ${identityName ?? "reference"} measured ${Number(identity.result_data.best_similarity).toFixed(3)} against threshold 0.60.`
    );
  }
  if (Number(propagation?.result_data?.match_count ?? 0) > 0) {
    caseFindings.push(String(propagation?.result_data?.summary ?? "Matching copy found in local index."));
  }
  if (caseFindings.length === 0) {
    caseFindings.push("Preserved original media with SHA-256 digest and ran applicable pipeline modules.");
  }

  const actions: Array<{ step: number; action: string; why: string; who_acts: string; deeptrace_role: string }> = [
    {
      step: 1,
      action: "Keep the unmodified original file and its SHA-256 digest intact",
      why: "Re-saving or forwarding through messaging apps changes the byte digest. Keep the original untouched.",
      who_acts: "The affected person or investigating officer.",
      deeptrace_role: "Preserved the original bytes and recorded the acquisition SHA-256.",
    },
  ];

  if (intervals.length > 0) {
    actions.push({
      step: actions.length + 1,
      action: "Manually review the flagged time windows",
      why: `Inspection flagged ${intervals.slice(0, 4).map((i) => i.label ?? `${i.start_seconds}s`).join(", ")}. Human review converts model indicators into verifiable observations.`,
      who_acts: "Investigator or forensic examiner.",
      deeptrace_role: "Supplies timestamps, sampled frames, and residual overlays.",
    });
  } else if (deepfake?.status === "completed") {
    actions.push({
      step: actions.length + 1,
      action: "Review the sampled frames manually",
      why: "No individual frame crossed the suspicion threshold, but sampling inspects discrete timestamps rather than every frame.",
      who_acts: "Investigator or forensic examiner.",
      deeptrace_role: "Supplies sampled frames and residual overlays.",
    });
  }

  if (identityName && identity?.result_data?.best_similarity !== undefined && identity?.result_data?.best_similarity !== null) {
    const sim = Number(identity.result_data.best_similarity);
    actions.push({
      step: actions.length + 1,
      action:
        sim >= 0.6
          ? `Confirm with ${identityName} that this media is not genuine`
          : "Re-check the reference photo before escalating identity claims",
      why:
        sim >= 0.6
          ? `Visual similarity (${sim.toFixed(2)}) exceeded 0.60. A first-person statement carries more weight than a similarity score.`
          : `Visual similarity (${sim.toFixed(2)}) was below 0.60. Re-enroll a clear frontal reference if needed.`,
      who_acts: "Investigator in coordination with the affected person.",
      deeptrace_role: "Provides the similarity measurement and reference record.",
    });
  } else {
    actions.push({
      step: actions.length + 1,
      action: "Enroll a consented reference identity if impersonation is alleged",
      why: "Without an enrolled reference, DeepTrace measures manipulation indicators without establishing whom the media depicts.",
      who_acts: "Affected person or investigator.",
      deeptrace_role: "Runs identity comparison once a consented reference exists.",
    });
  }

  if (voice?.status === "not_applicable") {
    actions.push({
      step: actions.length + 1,
      action: "Collect a 10–30 second reference voice sample if audio matters",
      why: "The submitted media contains audio, but no reference voice sample was enrolled.",
      who_acts: "Affected person or investigator.",
      deeptrace_role: "Runs voice comparison once a voice sample is enrolled.",
    });
  }

  if (traceSources.length > 0) {
    const fetched = traceSources.filter((s) => s.retrieval_status === "fetched").length;
    actions.push({
      step: actions.length + 1,
      action: "Submit platform takedown requests for recorded source URLs",
      why: `${traceSources.length} URL(s) recorded (${fetched} retrieved and hash-compared). Platform grievance channels act on specific URLs.`,
      who_acts: "Affected person or authorised representative.",
      deeptrace_role: "Preserved retrieved copies and computed hash/perceptual similarity.",
    });
  } else {
    actions.push({
      step: actions.length + 1,
      action: "Record where the media was found",
      why: "Platform takedowns and complaints require exact URLs where the media appeared.",
      who_acts: "Affected person or investigator.",
      deeptrace_role: "Retrieves and compares copies from public HTTPS URLs you supply.",
    });
  }

  const evidencePackage = [
    "Exported DeepTrace PDF report (hashes, per-module findings, custody boundary, validation caveats)",
    "Original submitted media, unmodified, with its recorded SHA-256",
  ];
  if (investigation.frames_extracted > 0) {
    evidencePackage.push(`${investigation.frames_extracted} preserved sampled frames with individual SHA-256 digests`);
  }
  if (traceSources.length > 0) {
    evidencePackage.push(`${traceSources.length} recorded source URL(s) and any retrieved copies`);
  }
  evidencePackage.push("Case timeline showing when each step ran");

  return {
    priority,
    risk_level: riskLevel,
    case_findings: caseFindings,
    recommended_actions: actions,
    evidence_package: evidencePackage,
    reporting_routes: REPORTING_ROUTES,
    deeptrace_boundary:
      "DeepTrace prepares and preserves evidence and explains the available routes. It does not file complaints, does not contact platforms or authorities, does not remove content, and does not identify who created the media.",
    caveats: [
      "Model outputs are forensic indicators, not proof of manipulation or of identity.",
      "DeepTrace does not identify the creator or uploader of the media.",
      "Hash-based preservation demonstrates local integrity; it is not third-party notarisation.",
      "Sampling examines a subset of frames; segments between samples were not analysed.",
    ],
  };
}
