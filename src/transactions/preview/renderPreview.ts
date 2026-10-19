import { TransactionPreview, RiskSeverity, DecisionAction } from "./types";


const SEVERITY_LABEL: Record<RiskSeverity, string> = {
  info: "ℹ️ Info",
  low: "🔹 Low",
  medium: "⚠️ Medium",
  high: "🚨 HIGH",
  critical: "⛔ CRITICAL",
};

const NETWORK_LABEL: Record<TransactionPreview["network"], string> = {
  public: "Stellar Mainnet (real funds)",
  testnet: "Stellar Testnet",
  futurenet: "Stellar Futurenet",
  unknown: "UNKNOWN NETWORK",
};

// Strip control and bidi-override characters an attacker could use to
// disguise memos, data names or asset codes in chat clients.
const UNSAFE_CHARS = new RegExp(
  // eslint-disable-next-line no-control-regex
  "[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]",
  "g"
);

export interface RenderOptions {
  /** Omit info-level flags (e.g. for compact chat replies). Default false. */
  hideInfo?: boolean;
}
export function sanitizeForDisplay(input: string): string {
  if (!input) return "";
  // Remove bidirectional override characters and replace control characters
  let sanitized = input.replace(/[\u202a-\u202e\u2066-\u2069]/g, "");
  // Replace other potential control characters with replacement character
  sanitized = sanitized.replace(/[\x00-\x1F\x7F-\x9F]/g, "\ufffd");
  return sanitized;
}

export function severityLabel(severity: RiskSeverity): string {
  switch (severity) {
    case "critical":
      return "🔴 CRITICAL RISK";
    case "high":
      return "🟠 HIGH RISK";
    case "medium":
      return "🟡 Medium Risk";
    case "low":
    default:
      return "🟢 Low Risk";
  }
}

export function renderPreviewText(preview: TransactionPreview): string {
  const lines: string[] = [];

  if (preview.decision === "refuse") {
    lines.push("⛔ TRANSACTION BLOCKED");
    lines.push(`Reason: ${sanitizeForDisplay(preview.decisionReason)}`);
  } else if (preview.decision === "confirm") {
    lines.push("⚠️ TRANSACTION REQUIRES CONFIRMATION");
    lines.push(`Reason: ${sanitizeForDisplay(preview.decisionReason)}`);
  } else {
    lines.push("✅ TRANSACTION PREVIEW (Safe)");
  }

  lines.push("");

  const isMainnet = preview.networkPassphrase.includes("Public Global Stellar Network");
  const networkDisplay = isMainnet
    ? "Stellar Mainnet (real funds)"
    : `Stellar Testnet / Network (${sanitizeForDisplay(preview.network)})`;
  lines.push(`Network: ${networkDisplay}`);
  lines.push(`Source Account: ${sanitizeForDisplay(preview.sourceAccount)}`);
  lines.push(`Fee: ${sanitizeForDisplay(preview.feeXlm)} XLM (${sanitizeForDisplay(preview.fee)} stroops)`);
  lines.push(`Sequence: ${sanitizeForDisplay(preview.sequence)}`);
  if (preview.memo) {
    lines.push(`Memo: ${sanitizeForDisplay(preview.memo)}`);
  }

  lines.push("");
  lines.push(`Overall Risk Level: ${severityLabel(preview.riskLevel)}`);

  if (preview.riskFlags.length > 0) {
    lines.push("Risk Warnings:");
    for (const flag of preview.riskFlags) {
      lines.push(` - [${flag.code}] (${flag.severity.toUpperCase()}) ${sanitizeForDisplay(flag.message)}`);
    }
    lines.push("");
  }

  lines.push(`Operations (${preview.operations.length}):`);
  for (const op of preview.operations) {
    lines.push(` ${op.index}. Type: ${op.type}`);
    lines.push(`    Summary: ${sanitizeForDisplay(op.summary)}`);
    lines.push(`    Asset: ${sanitizeForDisplay(op.asset)} | Amount: ${sanitizeForDisplay(op.amount)}`);
    if (op.destination) {
      lines.push(`    Destination: ${sanitizeForDisplay(op.destination)}`);
  }
  }

  if (preview.intent.compared) {
    lines.push("");
    if (preview.intent.matches) {
      lines.push("Intent Check: MATCHES user request");
    } else {
      lines.push("Intent Check: MISMATCH DETECTED!");
      for (const mismatch of preview.intent.mismatches) {
        lines.push(` - ${sanitizeForDisplay(mismatch)}`);
      }
    }
  }

  lines.push("");
  lines.push(`Audit Preview ID: ${preview.audit.previewId}`);
  return lines.join("\n");
}
