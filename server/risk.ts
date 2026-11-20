export const FACE_THRESHOLD = 0.60;
export const VOICE_THRESHOLD = 0.25;
export const MANIPULATION_THRESHOLD = 0.50;

export const WEIGHTS = {
  manipulation: 0.35,
  identity: 0.25,
  voice: 0.12,
  av_consistency: 0.10,
  provenance: 0.08,
  audio_editing: 0.05,
  propagation: 0.05,
} as const;

export const RISK_DISCLAIMER =
  "This score is an investigative prioritisation aid derived from forensic indicators. It is not proof of manipulation or of impersonation.";

function thresholdNormalise(value: number, threshold: number): number {
  if (value >= threshold) {
    const headroom = Math.max(1e-6, 1.0 - threshold);
    return Math.min(1.0, 0.5 + (0.5 * (value - threshold)) / headroom);
  }
  return threshold > 0 ? Math.max(0.0, 0.5 * (value / threshold)) : 0.0;
}

function bandFor(score: number): string {
  if (score >= 0.75) return "CRITICAL";
  if (score >= 0.50) return "HIGH";
  if (score >= 0.25) return "MEDIUM";
  return "LOW";
}

function levelFor(normalized: number): string {
  if (normalized >= 0.75) return "HIGH";
  if (normalized >= 0.50) return "MEDIUM";
  if (normalized >= 0.25) return "LOW";
  return "MINIMAL";
}

interface ModuleRecord {
  status: string;
  score: number | null;
  result_data: Record<string, unknown>;
}

export function fuseRiskSignals(params: {
  modules: Record<string, ModuleRecord | undefined>;
  identityName: string | null;
}) {
  const { modules, identityName } = params;

  interface CandidateSignal {
    key: string;
    label: string;
    raw_value: number;
    raw_units: string;
    threshold: number | null;
    normalized: number;
    normalization: string;
    direction: string;
    weight: number;
    level: string;
    detail: string;
    source_model: string;
  }

  const signals: CandidateSignal[] = [];
  const excluded: Array<{ key: string; label: string; reason: string }> = [];

  const deepfake = modules.deepfake;
  if (
    deepfake &&
    deepfake.status === "completed" &&
    deepfake.score !== null &&
    !deepfake.result_data.excluded_from_risk
  ) {
    const value = Number(deepfake.score);
    const normalized = thresholdNormalise(value, MANIPULATION_THRESHOLD);
    const modelName = String(deepfake.result_data.model_name ?? "Residual frequency analyzer");
    signals.push({
      key: "manipulation",
      label: "Manipulation detection",
      raw_value: Math.round(value * 1e6) / 1e6,
      raw_units: "manipulation indicator score (0..1)",
      threshold: MANIPULATION_THRESHOLD,
      normalized: Math.round(normalized * 1e6) / 1e6,
      normalization: `Threshold-anchored: ${MANIPULATION_THRESHOLD.toFixed(2)} maps to 0.50.`,
      direction: "Higher increases risk",
      weight: WEIGHTS.manipulation,
      level: levelFor(normalized),
      detail: `${modelName} returned a manipulation signal of ${value.toFixed(2)} for this media.`,
      source_model: modelName,
    });
  } else {
    excluded.push({
      key: "manipulation",
      label: "Manipulation detection",
      reason: String(deepfake?.result_data?.reason ?? "Visual manipulation analysis was unavailable or inapplicable."),
    });
  }

  const identity = modules.identity;
  if (
    identity &&
    identity.status === "completed" &&
    identity.result_data.best_similarity !== undefined &&
    identity.result_data.best_similarity !== null
  ) {
    const value = Number(identity.result_data.best_similarity);
    const normalized = thresholdNormalise(Math.max(0, value), FACE_THRESHOLD);
    const subject = String(identity.result_data.reference_identity ?? identityName ?? "the enrolled identity");
    signals.push({
      key: "identity",
      label: "Identity match",
      raw_value: Math.round(value * 1e6) / 1e6,
      raw_units: "cosine similarity of face descriptors",
      threshold: FACE_THRESHOLD,
      normalized: Math.round(normalized * 1e6) / 1e6,
      normalization: `Threshold-anchored: ${FACE_THRESHOLD.toFixed(2)} cosine maps to 0.50.`,
      direction: "Higher increases risk (media more likely depicts the protected identity)",
      weight: WEIGHTS.identity,
      level: levelFor(normalized),
      detail:
        value >= FACE_THRESHOLD
          ? `Best face similarity to ${subject} is ${value.toFixed(3)}, above the ${FACE_THRESHOLD.toFixed(2)} same-person threshold, so the media does appear to depict the protected identity.`
          : `Best face similarity to ${subject} is ${value.toFixed(3)}, below the ${FACE_THRESHOLD.toFixed(2)} same-person threshold.`,
      source_model: String(identity.result_data.model_name ?? "Normalized spatial-chroma descriptor"),
    });
  } else {
    excluded.push({
      key: "identity",
      label: "Identity match",
      reason: String(identity?.result_data?.reason ?? "No enrolled identity was compared against this media."),
    });
  }

  const voice = modules.voice;
  if (voice && voice.status === "completed" && voice.score !== null && !voice.result_data.excluded_from_risk) {
    const value = Number(voice.score);
    const normalized = thresholdNormalise(Math.max(0, value), VOICE_THRESHOLD);
    signals.push({
      key: "voice",
      label: "Voice match",
      raw_value: Math.round(value * 1e6) / 1e6,
      raw_units: "cosine similarity of audio envelope profile",
      threshold: VOICE_THRESHOLD,
      normalized: Math.round(normalized * 1e6) / 1e6,
      normalization: `Threshold-anchored: ${VOICE_THRESHOLD.toFixed(2)} cosine maps to 0.50.`,
      direction: "Higher increases risk",
      weight: WEIGHTS.voice,
      level: levelFor(normalized),
      detail: String(voice.result_data.interpretation ?? `Speaker similarity ${value.toFixed(3)}.`),
      source_model: String(voice.result_data.model_name ?? "16kHz PCM temporal profile"),
    });
  } else {
    excluded.push({
      key: "voice",
      label: "Voice match",
      reason: String(voice?.result_data?.reason ?? "Speaker comparison was not performed."),
    });
  }

  const consistency = modules.consistency;
  if (
    consistency &&
    consistency.status === "completed" &&
    consistency.score !== null &&
    !consistency.result_data.excluded_from_risk
  ) {
    const alignment = Number(consistency.score);
    const normalized = Math.max(0, Math.min(1, 1.0 - alignment));
    signals.push({
      key: "av_consistency",
      label: "Audio/video consistency",
      raw_value: Math.round(alignment * 1e6) / 1e6,
      raw_units: "share of sampled timestamps where face presence and audio activity agree",
      threshold: null,
      normalized: Math.round(normalized * 1e6) / 1e6,
      normalization: "Inverted — low alignment increases risk.",
      direction: "Lower alignment increases risk",
      weight: WEIGHTS.av_consistency,
      level: levelFor(normalized),
      detail: `Face presence and audio activity consistency measured at ${(alignment * 100).toFixed(0)}%.`,
      source_model: "FFprobe stream alignment + PCM RMS",
    });
  } else {
    excluded.push({
      key: "av_consistency",
      label: "Audio/video consistency",
      reason: String(consistency?.result_data?.reason ?? "Audio/video alignment could not be measured."),
    });
  }

  const provenance = modules.provenance;
  if (
    provenance &&
    provenance.status === "completed" &&
    provenance.score !== null &&
    !provenance.result_data.excluded_from_risk
  ) {
    const val = Number(provenance.score);
    signals.push({
      key: "provenance",
      label: "Content credentials (c2pa)",
      raw_value: val,
      raw_units: "provenance anomaly indicator",
      threshold: null,
      normalized: val,
      normalization: "Direct indicator.",
      direction: "Higher indicates provenance anomaly",
      weight: WEIGHTS.provenance,
      level: levelFor(val),
      detail: String(provenance.result_data.note ?? "Content Credentials inspected."),
      source_model: "Header byte JUMBF scanner",
    });
  } else {
    excluded.push({
      key: "provenance",
      label: "Content credentials (c2pa)",
      reason: String(provenance?.result_data?.note ?? "No C2PA manifest was attached (absence never raises risk)."),
    });
  }

  const audio = modules.audio;
  if (audio && audio.status === "completed" && audio.score !== null && !audio.result_data.excluded_from_risk) {
    const val = Number(audio.score);
    signals.push({
      key: "audio_editing",
      label: "Audio editing indicators",
      raw_value: Math.round(val * 1e6) / 1e6,
      raw_units: "splice & clipping indicator (0..1)",
      threshold: null,
      normalized: Math.round(val * 1e6) / 1e6,
      normalization: "Direct indicator.",
      direction: "Higher indicates abrupt RMS jumps or clipping",
      weight: WEIGHTS.audio_editing,
      level: levelFor(val),
      detail: `Audio discontinuity and clipping indicator scored ${val.toFixed(3)}.`,
      source_model: "PCM RMS discontinuity & clipping detector",
    });
  } else {
    excluded.push({
      key: "audio_editing",
      label: "Audio editing indicators",
      reason: String(audio?.result_data?.reason ?? "No decodable audio stream present."),
    });
  }

  const similarity = modules.similarity;
  if (
    similarity &&
    similarity.status === "completed" &&
    similarity.score !== null &&
    Number(similarity.score) > 0 &&
    !similarity.result_data.excluded_from_risk
  ) {
    const val = Number(similarity.score);
    signals.push({
      key: "propagation",
      label: "Local evidence propagation",
      raw_value: Math.round(val * 1e6) / 1e6,
      raw_units: "maximum similarity to prior local cases",
      threshold: null,
      normalized: Math.round(val * 1e6) / 1e6,
      normalization: "Direct similarity.",
      direction: "Higher indicates prior local redistribution",
      weight: WEIGHTS.propagation,
      level: levelFor(val),
      detail: String(similarity.result_data.summary ?? "Matching copy found in local evidence index."),
      source_model: "SHA-256 & 64-bit dHash local index",
    });
  } else {
    excluded.push({
      key: "propagation",
      label: "Local evidence propagation",
      reason: String(similarity?.result_data?.reason ?? "No matching media found in prior local cases."),
    });
  }

  const totalDeclaredWeight = signals.reduce((acc, s) => acc + s.weight, 0);
  if (signals.length === 0 || totalDeclaredWeight <= 0) {
    return {
      overall_risk_score: null,
      risk_level: "UNAVAILABLE",
      available_count: 0,
      excluded_count: excluded.length,
      signals: [],
      excluded,
      formula: "weighted sum of normalized available signals",
      total_declared_weight_available: 0,
      thresholds: {
        risk_bands: { CRITICAL: 0.75, HIGH: 0.5, MEDIUM: 0.25, LOW: 0.0 },
      },
      explanation: "Risk fusion could not run because no forensic signals produced a fusable score.",
      summary: "Risk fusion could not run because no forensic signals produced a fusable score.",
      disclaimer: RISK_DISCLAIMER,
    };
  }

  const weightedSignals = signals.map((s) => {
    const effective_weight = s.weight / totalDeclaredWeight;
    const contribution = s.normalized * effective_weight;
    return {
      ...s,
      effective_weight: Math.round(effective_weight * 1e6) / 1e6,
      contribution: Math.round(contribution * 1e6) / 1e6,
    };
  });

  const overall = Math.round(weightedSignals.reduce((acc, c) => acc + c.contribution, 0) * 1e6) / 1e6;
  const band = bandFor(overall);
  const top = [...weightedSignals].sort((a, b) => b.contribution - a.contribution)[0];

  const explanation =
    `Assessed ${band} impersonation risk (${overall.toFixed(2)} on a 0–1 scale) from ${weightedSignals.length} available forensic signal(s). ` +
    `The largest single contribution came from ${top.label.toLowerCase()} (${top.contribution.toFixed(3)} of the ${overall.toFixed(2)} total, at an effective weight of ${top.effective_weight.toFixed(2)}). ` +
    `${excluded.length} signal(s) were unavailable and excluded rather than assumed (${excluded.map((e) => e.label.toLowerCase()).join(", ")}); they neither raised nor lowered this score. ` +
    "These are forensic indicators for investigator review, not proof of manipulation or of identity.";

  return {
    overall_risk_score: overall,
    risk_level: band,
    available_count: weightedSignals.length,
    excluded_count: excluded.length,
    signals: weightedSignals,
    excluded,
    formula: "sum(normalized_i * (weight_i / sum_available_weights))",
    total_declared_weight_available: Math.round(totalDeclaredWeight * 1e4) / 1e4,
    thresholds: {
      risk_bands: { CRITICAL: 0.75, HIGH: 0.5, MEDIUM: 0.25, LOW: 0.0 },
    },
    explanation,
    summary: explanation,
    disclaimer: RISK_DISCLAIMER,
  };
}
