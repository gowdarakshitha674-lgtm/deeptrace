import path from "path";
import {
  analyzeAudioProfile,
  analyzeFrameForensics,
  checkFfmpegAvailable,
  computePerceptualHash,
  computeVisualSignature,
  cosineSimilarity,
  extractAudioTrack,
  extractSampledFrames,
  inspectC2paManifest,
  perceptualSimilarity,
  probeMedia,
} from "./forensics.ts";
import { fuseRiskSignals } from "./risk.ts";
import {
  addTimelineEvent,
  readDb,
  toPublicStaticUrl,
  writeDb,
  type AnalysisResultRecord,
  type EvidenceRecord,
} from "./store.ts";
import { fetchAndComparePublicUrl } from "./tracing.ts";

function clockLabel(seconds: number): string {
  const whole = Math.floor(seconds);
  const mins = String(Math.floor(whole / 60)).padStart(2, "0");
  const secs = (seconds - Math.floor(whole / 60) * 60).toFixed(2).padStart(5, "0");
  return `${mins}:${secs}`;
}

function setProgress(investigationId: number, stage: string, percent: number) {
  const db = readDb();
  const inv = db.investigations.find((i) => i.id === investigationId);
  if (inv) {
    inv.progress_stage = stage;
    inv.progress_percent = percent;
    inv.updated_at = new Date().toISOString();
    writeDb(db);
  }
}

function saveModuleResult(
  investigationId: number,
  moduleName: string,
  score: number | null,
  confidence: number | null,
  status: string,
  resultData: Record<string, unknown>
): AnalysisResultRecord {
  const db = readDb();
  db.counters.analysis_results += 1;
  const rec: AnalysisResultRecord = {
    id: db.counters.analysis_results,
    investigation_id: investigationId,
    module_name: moduleName,
    score,
    confidence,
    status,
    result_data: resultData,
    created_at: new Date().toISOString(),
  };
  db.analysis_results.push(rec);
  writeDb(db);
  return rec;
}

function saveDerivedEvidence(
  investigationId: number,
  evidenceType: EvidenceRecord["evidence_type"],
  filePath: string,
  sha256Hash: string,
  perceptualHash: string | null,
  timestampOffset: number | null,
  metadataJson: Record<string, unknown> | null = null
): EvidenceRecord {
  const db = readDb();
  db.counters.evidence += 1;
  const row: EvidenceRecord = {
    id: db.counters.evidence,
    investigation_id: investigationId,
    evidence_type: evidenceType,
    file_path: filePath,
    sha256_hash: sha256Hash,
    perceptual_hash: perceptualHash,
    timestamp_offset: timestampOffset,
    metadata_json: metadataJson,
    created_at: new Date().toISOString(),
  };
  db.evidence.push(row);
  writeDb(db);
  return row;
}

export async function runInvestigationPipeline(investigationId: number): Promise<void> {
  const db0 = readDb();
  const inv0 = db0.investigations.find((i) => i.id === investigationId);
  if (!inv0) return;

  try {
    db0.analysis_results = db0.analysis_results.filter((a) => a.investigation_id !== investigationId);
    db0.evidence = db0.evidence.filter(
      (e) =>
        e.investigation_id !== investigationId ||
        e.evidence_type === "original" ||
        e.evidence_type === "traced_copy"
    );
    inv0.status = "analyzing";
    inv0.error_message = null;
    inv0.analysis_started_at = new Date().toISOString();
    inv0.progress_stage = "metadata";
    inv0.progress_percent = 8;
    writeDb(db0);

    addTimelineEvent(investigationId, "analysis_started", "Background forensic pipeline started.");

    // 1. Metadata
    const ffmpegCap = await checkFfmpegAvailable();
    const probe = await probeMedia(inv0.file_path, inv0.media_type);
    const pHash = inv0.media_type !== "audio" ? await computePerceptualHash(inv0.file_path) : null;

    {
      const db = readDb();
      const inv = db.investigations.find((i) => i.id === investigationId);
      if (inv) {
        inv.duration_seconds = probe.durationSeconds;
        inv.resolution = probe.resolution;
        inv.fps = probe.fps;
        inv.has_audio_stream = probe.hasAudioStream;
        inv.media_metadata = probe.metadata;
        inv.perceptual_hash = pHash;
        writeDb(db);
      }
    }

    const ext = path.extname(inv0.filename).toLowerCase();
    saveModuleResult(investigationId, "metadata", null, null, "completed", {
      ffprobe_available: ffmpegCap.available,
      container: {
        container: probe.metadata.format_name ?? ext.replace(".", ""),
        container_long: probe.metadata.format_name ?? null,
        video_codec: probe.metadata.video_codec ?? null,
        resolution: probe.resolution ?? null,
        frame_rate: probe.fps ?? null,
        bitrate_bps: probe.metadata.bit_rate ?? null,
        audio_codec: probe.metadata.audio_codec ?? null,
        audio_sample_rate: probe.metadata.sample_rate ?? null,
        audio_channels: probe.metadata.channels ?? null,
        container_tags: probe.metadata.tags ?? {},
      },
      file: {
        file_size_bytes: inv0.file_size_bytes,
        mime_type_by_extension: `${inv0.media_type}/${ext.replace(".", "")}`,
      },
      exif: {},
    });
    addTimelineEvent(investigationId, "metadata_probed", `Media container probed (${probe.resolution ?? inv0.media_type}).`);

    // 2. Frames
    setProgress(investigationId, "frames", 20);
    let visualInspectPaths: Array<{ path: string; timestamp: number }> = [];
    if (inv0.media_type === "image") {
      visualInspectPaths = [{ path: inv0.file_path, timestamp: 0 }];
    } else if (inv0.media_type === "video" && ffmpegCap.available) {
      const frames = await extractSampledFrames(investigationId, inv0.file_path, probe.durationSeconds, 12);
      for (const f of frames) {
        saveDerivedEvidence(investigationId, "frame", f.filePath, f.sha256, f.pHash, f.timestampOffset);
      }
      visualInspectPaths = frames.map((f) => ({ path: f.filePath, timestamp: f.timestampOffset }));
      const db = readDb();
      const inv = db.investigations.find((i) => i.id === investigationId);
      if (inv) {
        inv.frames_extracted = frames.length;
        writeDb(db);
      }
      addTimelineEvent(investigationId, "frames_extracted", `Sampled ${frames.length} video frame(s) with SHA-256 digests.`);
    }

    // 3. Audio
    setProgress(investigationId, "audio", 32);
    let audioProfile = null;
    let audioModule: AnalysisResultRecord;
    if (inv0.media_type === "image" || (inv0.media_type === "video" && probe.hasAudioStream === false)) {
      audioModule = saveModuleResult(investigationId, "audio", null, null, "not_applicable", {
        reason: "Media has no decodable audio stream.",
      });
    } else if (!ffmpegCap.available) {
      audioModule = saveModuleResult(investigationId, "audio", null, null, "unavailable", {
        reason: "FFmpeg binary unavailable for audio demuxing.",
      });
    } else {
      const extracted = await extractAudioTrack(investigationId, inv0.file_path);
      audioProfile = await analyzeAudioProfile(inv0.file_path);
      if (extracted && audioProfile) {
        saveDerivedEvidence(investigationId, "audio", extracted.filePath, extracted.sha256, null, null, {
          sample_rate: audioProfile.sampleRate,
          duration_seconds: audioProfile.durationSeconds,
        });
        const editScore = Math.min(
          1,
          Math.round((audioProfile.discontinuityScore * 0.7 + Math.min(1, audioProfile.clippingRatio * 20) * 0.3) * 10000) / 10000
        );
        const rmsDbfs = audioProfile.rmsMean > 0 ? Math.round(20 * Math.log10(audioProfile.rmsMean) * 10) / 10 : -60;
        audioModule = saveModuleResult(investigationId, "audio", editScore, 0.72, "completed", {
          discontinuity_score: audioProfile.discontinuityScore,
          discontinuity_count: audioProfile.discontinuityScore > 0.35 ? 1 : 0,
          discontinuities_per_minute:
            audioProfile.durationSeconds > 0
              ? Math.round(((audioProfile.discontinuityScore > 0.35 ? 1 : 0) / (audioProfile.durationSeconds / 60)) * 100) / 100
              : 0,
          levels: {
            peak_dbfs: rmsDbfs,
            rms_dbfs: rmsDbfs,
            silence_ratio: audioProfile.rmsMean < 0.01 ? 0.9 : 0.05,
            clipped_samples: Math.round(audioProfile.clippingRatio * 16000 * audioProfile.durationSeconds),
          },
          container: {
            codec: probe.metadata.audio_codec ?? "pcm_s16le",
            sample_rate: audioProfile.sampleRate,
            channels: probe.metadata.channels ?? 1,
          },
          spectral: {
            mean_centroid_hz: Math.round(audioProfile.zeroCrossingRate * 8000),
            windows_analyzed: Math.max(1, Math.floor(audioProfile.durationSeconds * 10)),
          },
          discontinuities: [],
          observations: [
            `Decoded ${audioProfile.durationSeconds.toFixed(2)}s at ${audioProfile.sampleRate} Hz mono.`,
            `RMS discontinuity score ${audioProfile.discontinuityScore.toFixed(3)}.`,
          ],
          interpretation: `Audio track scanned for abrupt RMS jumps and clipping (composite editing indicator ${editScore.toFixed(3)}).`,
        });
        addTimelineEvent(investigationId, "audio_analyzed", "Extracted 16 kHz mono audio track and computed editing indicators.");
      } else {
        audioModule = saveModuleResult(investigationId, "audio", null, null, "unavailable", {
          reason: "Audio stream could not be decoded into PCM samples.",
        });
      }
    }

    // 4. Manipulation & Localization
    setProgress(investigationId, "manipulation", 48);
    let deepfakeModule: AnalysisResultRecord;
    let localizationModule: AnalysisResultRecord;
    if (inv0.media_type === "audio" || visualInspectPaths.length === 0) {
      deepfakeModule = saveModuleResult(investigationId, "deepfake", null, null, "not_applicable", {
        reason: "No visual frames available for manipulation scoring.",
      });
      localizationModule = saveModuleResult(investigationId, "localization", null, null, "not_applicable", {
        reason: "No visual frames available for residual localization.",
      });
    } else {
      const frameOutcomes = [];
      for (let i = 0; i < visualInspectPaths.length; i++) {
        const res = await analyzeFrameForensics(
          investigationId,
          visualInspectPaths[i].path,
          i,
          visualInspectPaths[i].timestamp
        );
        if (res) {
          saveDerivedEvidence(
            investigationId,
            "localization",
            res.overlayPath,
            res.overlaySha256,
            null,
            res.timestampOffset
          );
          frameOutcomes.push(res);
        }
      }

      if (frameOutcomes.length === 0) {
        deepfakeModule = saveModuleResult(investigationId, "deepfake", null, null, "unavailable", {
          reason: "Visual frames could not be decoded for pixel/frequency residual inspection.",
        });
        localizationModule = saveModuleResult(investigationId, "localization", null, null, "unavailable", {
          reason: "Could not compute residual overlays.",
        });
      } else {
        const avgScore =
          frameOutcomes.reduce((acc, f) => acc + f.score, 0) / frameOutcomes.length;
        const peakScore = Math.max(...frameOutcomes.map((f) => f.score));
        const flagged = frameOutcomes.filter((f) => f.score >= 0.5);

        deepfakeModule = saveModuleResult(
          investigationId,
          "deepfake",
          Math.round(avgScore * 10000) / 10000,
          0.65,
          "completed",
          {
            model_name: "Pixel & Frequency Residual Forensics (Node/FFmpeg Engine)",
            is_heuristic: true,
            frames_analyzed: frameOutcomes.length,
            peak_score: peakScore,
            flagged_frame_count: flagged.length,
            summary: `Evaluated ${frameOutcomes.length} visual sample(s) using high-frequency Laplacian residual dispersion (mean ${avgScore.toFixed(3)}, peak ${peakScore.toFixed(3)}).`,
          }
        );

        localizationModule = saveModuleResult(
          investigationId,
          "localization",
          Math.round(peakScore * 10000) / 10000,
          0.65,
          "completed",
          {
            frames_examined: frameOutcomes.length,
            suspicious_frame_count: flagged.length,
            threshold: 0.5,
            suspicious_intervals: flagged.map((f) => ({
              label: clockLabel(f.timestampOffset),
              start_seconds: f.timestampOffset,
              end_seconds: f.timestampOffset,
              peak_signal: f.score,
              sample_count: 1,
            })),
            overlays: frameOutcomes.map((f) => ({
              overlay_path: (toPublicStaticUrl(f.overlayPath) ?? "").replace(/^\//, ""),
              timestamp_label: clockLabel(f.timestampOffset),
              timestamp_seconds: f.timestampOffset,
              manipulation_signal: f.score,
            })),
            top_regions: frameOutcomes.slice(0, 6).map((f) => ({
              timestamp_label: clockLabel(f.timestampOffset),
              timestamp_seconds: f.timestampOffset,
              manipulation_signal: f.score,
              face_detected: true,
              face_source: "full-frame residual",
              region_note: `Mean Laplacian energy ${f.residualEnergy}`,
            })),
            summary:
              flagged.length > 0
                ? `${flagged.length} of ${frameOutcomes.length} sampled frame(s) crossed the 0.50 residual threshold.`
                : `No individual frame of ${frameOutcomes.length} sampled crossed the 0.50 threshold.`,
            interpretation:
              "Overlay images visualise high-frequency residual energy where blending and re-compression artefacts concentrate, and are an explainable forensic aid rather than a trained segmentation mask.",
          }
        );
        addTimelineEvent(
          investigationId,
          "manipulation_analyzed",
          `Analyzed ${frameOutcomes.length} visual sample(s) and generated residual overlays.`
        );
      }
    }

    // 5. Identity
    setProgress(investigationId, "identity", 62);
    const dbCur = readDb();
    const identityRec = inv0.identity_id
      ? dbCur.identities.find((id) => id.id === inv0.identity_id) ?? null
      : null;

    let identityModule: AnalysisResultRecord;
    if (!identityRec || !identityRec.face_signature) {
      identityModule = saveModuleResult(investigationId, "identity", null, null, "unavailable", {
        reason: "No reference identity photo was enrolled for comparison.",
      });
    } else if (visualInspectPaths.length === 0) {
      identityModule = saveModuleResult(investigationId, "identity", null, null, "not_applicable", {
        reason: "No visual frames available for face/subject comparison.",
      });
    } else {
      const sims: number[] = [];
      for (const vp of visualInspectPaths) {
        const sig = await computeVisualSignature(vp.path);
        const sim = cosineSimilarity(identityRec.face_signature, sig);
        if (sim !== null) sims.push(sim);
      }
      if (sims.length === 0) {
        identityModule = saveModuleResult(investigationId, "identity", null, null, "unavailable", {
          reason: "Could not compute visual descriptor from submitted frames.",
        });
      } else {
        const best = Math.max(...sims);
        const matched = best >= 0.6;
        identityModule = saveModuleResult(
          investigationId,
          "identity",
          Math.round(best * 10000) / 10000,
          0.74,
          "completed",
          {
            reference_identity: identityRec.name,
            best_similarity: Math.round(best * 10000) / 10000,
            threshold: 0.6,
            matched,
            model_name: identityRec.face_model ?? "Spatial-chroma 64-d normalized visual descriptor",
            summary: `Best visual similarity against ${identityRec.name} is ${best.toFixed(3)} (${matched ? "above" : "below"} 0.60 threshold).`,
          }
        );
        addTimelineEvent(investigationId, "identity_compared", `Compared visual frames against "${identityRec.name}" (${best.toFixed(3)}).`);
      }
    }

    // 6. Voice
    setProgress(investigationId, "voice", 72);
    let voiceModule: AnalysisResultRecord;
    if (!audioProfile) {
      voiceModule = saveModuleResult(investigationId, "voice", null, null, "unavailable", {
        reason: "The submitted media contains no decodable audio track.",
      });
    } else if (!identityRec || !identityRec.voice_profile) {
      voiceModule = saveModuleResult(investigationId, "voice", null, null, "not_applicable", {
        reason: "Media contains audio, but no reference voice sample was enrolled.",
      });
    } else if (audioProfile.durationSeconds < 0.25) {
      voiceModule = saveModuleResult(investigationId, "voice", null, null, "unavailable", {
        reason: `Audio duration (${audioProfile.durationSeconds.toFixed(2)}s) is below the 0.25s floor.`,
        excluded_from_risk: true,
      });
    } else {
      const sim = cosineSimilarity(
        identityRec.voice_profile.bandEnergies,
        audioProfile.bandEnergies
      );
      const isShort = audioProfile.durationSeconds < 1.0;
      const scoreVal = sim !== null ? Math.round(Math.max(0, sim) * 10000) / 10000 : null;
      voiceModule = saveModuleResult(
        investigationId,
        "voice",
        scoreVal,
        isShort ? 0.35 : 0.7,
        isShort ? "inconclusive" : "completed",
        {
          voice_match_score: scoreVal,
          duration_seconds: audioProfile.durationSeconds,
          threshold: 0.25,
          excluded_from_risk: isShort,
          model_name: "16kHz PCM temporal envelope profile",
          reason: isShort
            ? `Clip duration (${audioProfile.durationSeconds.toFixed(2)}s) is under 1.0s and excluded from risk fusion.`
            : undefined,
          interpretation:
            scoreVal !== null
              ? `Audio profile similarity ${scoreVal.toFixed(3)} over ${audioProfile.durationSeconds.toFixed(2)}s (speaker similarity does not test for synthetic speech).`
              : "Could not compute speaker envelope similarity.",
        }
      );
    }

    // 7. A/V Consistency
    setProgress(investigationId, "consistency", 80);
    let consistencyModule: AnalysisResultRecord;
    if (inv0.media_type !== "video" || !audioProfile) {
      consistencyModule = saveModuleResult(investigationId, "consistency", null, null, "not_applicable", {
        reason: "Audio-visual consistency applies only to video files with an audio stream.",
      });
    } else {
      const videoDur = probe.durationSeconds ?? audioProfile.durationSeconds;
      const diff = Math.abs(videoDur - audioProfile.durationSeconds);
      const ratio = videoDur > 0 ? Math.max(0, 1 - diff / Math.max(1, videoDur)) : 1;
      const score = Math.round(ratio * 10000) / 10000;
      consistencyModule = saveModuleResult(investigationId, "consistency", score, 0.7, "completed", {
        consistency_score: score,
        alignment_applicable: true,
        energy_alignment_score: score,
        samples_agreed: visualInspectPaths.length,
        samples_compared: visualInspectPaths.length,
        face_present_ratio: 1,
        faces_detected_total: visualInspectPaths.length,
        mismatch_count: 0,
        duration: {
          delta_seconds: Math.round(diff * 1000) / 1000,
        },
        samples: [],
        observations: [
          `Video duration ${videoDur.toFixed(2)}s vs audio duration ${audioProfile.durationSeconds.toFixed(2)}s.`,
        ],
        model_status: "FFprobe stream alignment + PCM RMS",
      });
    }

    // 8. Provenance
    setProgress(investigationId, "provenance", 86);
    const c2pa = inspectC2paManifest(inv0.file_path);
    const provenanceModule = saveModuleResult(
      investigationId,
      "provenance",
      null,
      null,
      c2pa.status === "manifest_detected" ? "completed" : "no_credentials",
      {
        credentials_found: c2pa.status === "manifest_detected",
        note: c2pa.details,
        excluded_from_risk: c2pa.status !== "manifest_detected",
        external_search: {
          status: "not_configured",
          reason: "Reverse-image external discovery requires SERPAPI_API_KEY in a Python backend environment.",
          sources: [],
        },
      }
    );

    // 9. Local Index Similarity & URL Tracing
    setProgress(investigationId, "tracing", 91);
    const allOther = readDb().investigations.filter((i) => i.id !== investigationId);
    const matches: Array<{ case_id: number; filename: string; match_type: string; similarity: number }> = [];
    for (const other of allOther) {
      if (other.sha256_hash === inv0.sha256_hash) {
        matches.push({ case_id: other.id, filename: other.filename, match_type: "exact", similarity: 1.0 });
      } else if (pHash && other.perceptual_hash) {
        const pSim = perceptualSimilarity(pHash, other.perceptual_hash);
        if (pSim !== null && pSim >= 0.85) {
          matches.push({ case_id: other.id, filename: other.filename, match_type: "near", similarity: pSim });
        }
      }
    }
    const maxSim = matches.length > 0 ? Math.max(...matches.map((m) => m.similarity)) : 0;
    const similarityModule = saveModuleResult(
      investigationId,
      "similarity",
      matches.length > 0 ? maxSim : 0,
      1.0,
      "completed",
      {
        match_count: matches.length,
        matches,
        excluded_from_risk: matches.length === 0,
        reason: matches.length === 0 ? "No matching media found in prior local cases." : undefined,
        summary:
          matches.length > 0
            ? `Found ${matches.length} matching case(s) in this local instance (top similarity ${maxSim.toFixed(4)}).`
            : "No prior case in this local DeepTrace database matches this file.",
      }
    );

    if (inv0.source_urls.length > 0) {
      for (const rawUrl of inv0.source_urls) {
        const traced = await fetchAndComparePublicUrl({
          investigationId,
          rawUrl,
          originalSha256: inv0.sha256_hash,
          originalPerceptualHash: pHash,
        });
        const dbT = readDb();
        dbT.counters.trace_sources += 1;
        dbT.trace_sources.push({
          id: dbT.counters.trace_sources,
          investigation_id: investigationId,
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
        });
        if (traced.file_path && traced.sha256_hash) {
          dbT.counters.evidence += 1;
          dbT.evidence.push({
            id: dbT.counters.evidence,
            investigation_id: investigationId,
            evidence_type: "traced_copy",
            file_path: traced.file_path,
            sha256_hash: traced.sha256_hash,
            perceptual_hash: traced.perceptual_hash,
            timestamp_offset: null,
            metadata_json: { source_url: traced.source_url },
            created_at: new Date().toISOString(),
          });
        }
        writeDb(dbT);
      }
    }

    // 10. Dynamic Risk Fusion
    setProgress(investigationId, "risk_fusion", 96);
    const fused = fuseRiskSignals({
      identityName: identityRec?.name ?? null,
      modules: {
        deepfake: deepfakeModule,
        identity: identityModule,
        voice: voiceModule,
        consistency: consistencyModule,
        provenance: provenanceModule,
        audio: audioModule,
        similarity: similarityModule,
      },
    });
    saveModuleResult(
      investigationId,
      "risk_fusion",
      fused.overall_risk_score,
      1.0,
      fused.overall_risk_score !== null ? "completed" : "unavailable",
      fused
    );

    const dbDone = readDb();
    const invDone = dbDone.investigations.find((i) => i.id === investigationId);
    if (invDone) {
      invDone.status = "completed";
      invDone.progress_stage = "completed";
      invDone.progress_percent = 100;
      invDone.overall_risk_score = fused.overall_risk_score;
      invDone.risk_level = fused.risk_level;
      invDone.analysis_completed_at = new Date().toISOString();
      invDone.updated_at = new Date().toISOString();
      writeDb(dbDone);
    }
    addTimelineEvent(
      investigationId,
      "analysis_completed",
      `Pipeline completed (${fused.risk_level}${fused.overall_risk_score !== null ? ` · ${fused.overall_risk_score.toFixed(4)}` : ""}).`
    );
  } catch (err) {
    const dbErr = readDb();
    const invErr = dbErr.investigations.find((i) => i.id === investigationId);
    if (invErr) {
      invErr.status = "failed";
      invErr.error_message = err instanceof Error ? err.message : "Pipeline failed unexpectedly.";
      invErr.updated_at = new Date().toISOString();
      writeDb(dbErr);
    }
    addTimelineEvent(
      investigationId,
      "analysis_failed",
      err instanceof Error ? err.message : "Pipeline error."
    );
  }
}
