import fs from "fs";
import PDFDocument from "pdfkit";
import { CUSTODY_SCOPE, REPORTING_ROUTES } from "./custodyAndResponse.ts";
import { sha256File } from "./forensics.ts";
import {
  reportFilePath,
  type AnalysisResultRecord,
  type EvidenceRecord,
  type IdentityRecord,
  type InvestigationRecord,
  type SubmitterRecord,
  type TimelineEventRecord,
  type TraceSourceRecord,
} from "./store.ts";

export async function generateForensicPdfReport(params: {
  investigation: InvestigationRecord;
  submitter: SubmitterRecord | null;
  identity: IdentityRecord | null;
  analyses: AnalysisResultRecord[];
  evidence: EvidenceRecord[];
  timeline: TimelineEventRecord[];
  traceSources: TraceSourceRecord[];
  verification: ReturnType<typeof import("./forensics.ts").verifyEvidenceArtifacts>;
}): Promise<{ filePath: string; sizeBytes: number; sha256: string }> {
  const {
    investigation,
    submitter,
    identity,
    analyses,
    evidence,
    timeline,
    traceSources,
    verification,
  } = params;

  const outPath = reportFilePath(investigation.id);

  await new Promise<void>((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48, size: "A4" });
    const stream = fs.createWriteStream(outPath);
    doc.pipe(stream);

    const h1 = (title: string) => {
      doc.moveDown(0.7);
      doc.font("Helvetica-Bold").fontSize(13).fillColor("#0F172A").text(title);
      doc.moveTo(48, doc.y + 2).lineTo(547, doc.y + 2).strokeColor("#CBD5E1").lineWidth(0.7).stroke();
      doc.moveDown(0.5);
    };

    const kv = (k: string, v: string) => {
      doc.font("Helvetica-Bold").fontSize(9.5).fillColor("#334155").text(`${k}: `, { continued: true });
      doc.font("Helvetica").fontSize(9.5).fillColor("#0F172A").text(v);
    };

    // Cover / Header
    doc.font("Helvetica-Bold").fontSize(18).fillColor("#0F172A").text("DeepTrace Forensic Evidence Dossier");
    doc.font("Helvetica").fontSize(10).fillColor("#475569").text(
      `Case #${investigation.id} · Generated ${new Date().toISOString()} · Investigative Indicators Only (Not Legal Proof)`
    );

    h1("1. Executive Case Summary");
    kv("Filename", investigation.filename);
    kv("Media Type", investigation.media_type);
    kv("File Size", `${investigation.file_size_bytes} bytes`);
    kv("Original SHA-256", investigation.sha256_hash);
    kv("Perceptual Hash (dHash)", investigation.perceptual_hash ?? "Not computed");
    kv("Overall Risk Score", investigation.overall_risk_score !== null ? investigation.overall_risk_score.toFixed(4) : "Unavailable");
    kv("Risk Band", investigation.risk_level ?? "UNAVAILABLE");
    kv("Reference Identity", identity ? `${identity.name} (Consent v${identity.consent_text_version})` : "None attached");

    h1("2. Self-Declared Submitter Details");
    if (submitter) {
      const maskedAadhaar = `XXXX XXXX ${submitter.aadhaar_number.slice(-4)}`;
      const maskedPhone = `+91 ******${submitter.phone_number.slice(-4)}`;
      kv("Full Name", submitter.full_name);
      kv("Aadhaar (masked)", maskedAadhaar);
      kv("Phone (masked)", maskedPhone);
      kv("Gender", submitter.gender);
      kv("Date of Birth", submitter.date_of_birth);
      doc.font("Helvetica-Oblique").fontSize(8.5).fillColor("#64748B").text(
        "Note: Identification fields are self-declared at intake and are not verified against UIDAI or telecom databases."
      );
    } else {
      doc.font("Helvetica").fontSize(9.5).text("No submitter record attached.");
    }

    h1("3. Media Metadata & Container Probe");
    kv("Resolution", investigation.resolution ?? "N/A");
    kv("Duration", investigation.duration_seconds !== null ? `${investigation.duration_seconds}s` : "N/A");
    kv("FPS", investigation.fps !== null ? String(investigation.fps) : "N/A");
    kv("Audio Stream", investigation.has_audio_stream ? "Present" : "Absent / N/A");
    kv("Frames Extracted", String(investigation.frames_extracted));

    h1("4. Module Findings & Excluded Signals");
    for (const mod of analyses) {
      doc.font("Helvetica-Bold").fontSize(10).fillColor("#0F172A").text(
        `${mod.module_name.toUpperCase()} — status: ${mod.status}${mod.score !== null ? ` · score: ${mod.score.toFixed(4)}` : ""}`
      );
      const summary =
        typeof mod.result_data.summary === "string"
          ? mod.result_data.summary
          : typeof mod.result_data.reason === "string"
            ? mod.result_data.reason
            : typeof mod.result_data.details === "string"
              ? mod.result_data.details
              : "";
      if (summary) {
        doc.font("Helvetica").fontSize(9).fillColor("#334155").text(summary);
      }
      doc.moveDown(0.25);
    }

    h1("5. Evidence Register & SHA-256 Verification");
    kv("Verification Status", verification.summary);
    doc.moveDown(0.3);
    for (const item of evidence.slice(0, 40)) {
      doc.font("Helvetica").fontSize(8.5).fillColor("#0F172A").text(
        `[#${item.id}] ${item.evidence_type} · ${item.file_path.split(/[\\/]/).pop()} · SHA-256: ${item.sha256_hash ?? "none"}`
      );
    }

    h1("6. Chain of Custody Scope Boundary");
    doc.font("Helvetica").fontSize(9).fillColor("#334155").text(CUSTODY_SCOPE.statement);
    doc.moveDown(0.25);
    doc.font("Helvetica-Bold").fontSize(9).text("DeepTrace Supplies (File Half):");
    for (const line of CUSTODY_SCOPE.deeptrace_supplies) {
      doc.font("Helvetica").fontSize(8.5).text(`• ${line}`);
    }
    doc.moveDown(0.25);
    doc.font("Helvetica-Bold").fontSize(9).text("Investigator Supplies (Custodial Half):");
    for (const line of CUSTODY_SCOPE.investigator_supplies) {
      doc.font("Helvetica").fontSize(8.5).text(`• ${line}`);
    }

    h1("7. Traced Public Sources & Local Copies");
    if (traceSources.length === 0) {
      doc.font("Helvetica").fontSize(9).text("No public URLs or external copies attached.");
    } else {
      for (const src of traceSources) {
        doc.font("Helvetica").fontSize(8.5).text(
          `${src.source_url ?? "Local copy"} — ${src.retrieval_status}${src.similarity !== null ? ` · similarity ${src.similarity.toFixed(4)} (${src.match_type})` : ""}${src.retrieval_error ? ` · ${src.retrieval_error}` : ""}`
        );
      }
    }

    h1("8. Chronological Audit Timeline");
    for (const ev of timeline) {
      doc.font("Helvetica").fontSize(8.5).fillColor("#334155").text(
        `${ev.created_at} [${ev.event_type}] ${ev.description}`
      );
    }

    h1("9. Official Reporting Routes & Disclaimers");
    for (const route of REPORTING_ROUTES) {
      doc.font("Helvetica-Bold").fontSize(9).fillColor("#0F172A").text(route.route);
      doc.font("Helvetica").fontSize(8.5).fillColor("#334155").text(`${route.detail} (${route.who_acts})`);
      doc.moveDown(0.2);
    }

    doc.end();
    stream.on("finish", resolve);
    stream.on("error", reject);
  });

  const stat = fs.statSync(outPath);
  const sha256 = sha256File(outPath);
  return { filePath: outPath, sizeBytes: stat.size, sha256 };
}
