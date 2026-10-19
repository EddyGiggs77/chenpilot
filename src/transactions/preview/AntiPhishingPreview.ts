import { createHash, randomUUID } from "crypto";
import * as StellarSdk from "@stellar/stellar-sdk";
import { decodeOperation, formatAsset } from "./operationDecoder";
import { assessOperation, maxSeverity, SEVERITY_ORDER } from "./riskAssessment";
import {
  BuildPreviewInput,
  IntentComparison,
  IntentMismatch,
  PreviewDecision,
  PreviewNetwork,
  PreviewOperation,
  RiskFlag,
  TransactionIntent,
  TransactionPreview,
} from "./types";

const NETWORK_PASSPHRASES: Record<string, PreviewNetwork> = {
  "Public Global Stellar Network ; September 2015": "public",
  "Test SDF Network ; September 2015": "testnet",
  "Test SDF Future Network ; October 2022": "futurenet",
};

export function detectAntiPhishingNetwork(passphrase: string): PreviewNetwork {
  return NETWORK_PASSPHRASES[passphrase] ?? "unknown";
}

const STROOPS_PER_UNIT = BigInt(10_000_000);

export function convertToStroops(amount: string): bigint {
  const trimmed = amount.trim();
  if (!/^\d+(\.\d{1,7})?$/.test(trimmed)) {
    throw new Error(`Invalid amount: ${amount}`);
  }
  const [whole, fraction = ""] = trimmed.split(".");
  return BigInt(whole) * STROOPS_PER_UNIT + BigInt(fraction.padEnd(7, "0"));
}

function stroopsToXlmAmount(stroops: bigint): string {
  const whole = stroops / STROOPS_PER_UNIT;
  const fraction = (stroops % STROOPS_PER_UNIT).toString().padStart(7, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function stableJsonStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJsonStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((k) => record[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableJsonStringify(record[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function computeSha256(value: unknown): string {
  return createHash("sha256").update(stableJsonStringify(value)).digest("hex");
}

function extractMemo(memo: StellarSdk.Memo): string | null {
  switch (memo.type) {
    case "none":
      return null;
    case "text":
      return Buffer.isBuffer(memo.value) ? memo.value.toString("utf8") : String(memo.value);
    case "id":
      return String(memo.value);
    default:
      return Buffer.isBuffer(memo.value) ? `${memo.type}:${memo.value.toString("hex")}` : `${memo.type}:${String(memo.value)}`;
  }
}

function checkAssetMatch(expected: string, actual: string): boolean {
  const norm = (a: string) => (a.toUpperCase() === "NATIVE" ? "XLM" : a.toUpperCase());
  const e = norm(expected);
  const a = norm(actual);
  return e.includes(":") ? e === a : e === a.split(":")[0];
}

export function compareAgainstIntent(
  operations: PreviewOperation[],
  network: PreviewNetwork,
  intent?: TransactionIntent
): IntentComparison {
  if (!intent) return { compared: false, matches: true, mismatches: [] };

  const mismatches: IntentMismatch[] = [];
  if (intent.network && intent.network !== network) {
    mismatches.push({
      field: "network",
      expected: intent.network,
      actual: network,
      severity: "critical",
    });
  }

  if (intent.operationTypes && intent.operationTypes.length > 0) {
    for (const [index, op] of operations.entries()) {
      if (!intent.operationTypes.includes(op.type)) {
        mismatches.push({
          field: "operationType",
          expected: intent.operationTypes.join(", "),
          actual: op.type,
          operationIndex: index,
          severity: "high",
        });
      }
    }
  }

  if (intent.destination) {
    for (const [index, op] of operations.entries()) {
      if (op.destination && op.destination !== intent.destination) {
        mismatches.push({
          field: "destination",
          expected: intent.destination,
          actual: op.destination,
          operationIndex: index,
          severity: "critical",
        });
      }
    }
  }

  if (intent.asset || intent.amount) {
    for (const [index, op] of operations.entries()) {
      if (intent.asset && op.asset && !checkAssetMatch(intent.asset, op.asset)) {
        mismatches.push({
          field: "asset",
          expected: intent.asset,
          actual: op.asset,
          operationIndex: index,
          severity: "high",
        });
      }
      if (intent.amount && op.amount) {
        try {
          const expectedStroops = convertToStroops(intent.amount);
          const actualStroops = convertToStroops(op.amount);
          if (actualStroops > expectedStroops) {
            mismatches.push({
              field: "amount",
              expected: intent.amount,
              actual: op.amount,
              operationIndex: index,
              severity: actualStroops > expectedStroops * 2n ? "critical" : "high",
            });
          }
        } catch {
          // ignore parsing errors
        }
      }
    }
  }

  const criticalOrHighMismatch = mismatches.some((m) => m.severity === "critical" || m.severity === "high");
  return {
    compared: true,
    matches: mismatches.length === 0,
    mismatches,
  };
}

export function buildAntiPhishingPreview(input: BuildPreviewInput): TransactionPreview {
  const tx = StellarSdk.TransactionBuilder.fromXDR(input.xdr, input.networkPassphrase);
  const network = detectAntiPhishingNetwork(input.networkPassphrase);
  const sourceAccount = tx.source;
  const isFeeBump = tx.isFeeBump?.() ?? false;
  const feeSource = isFeeBump ? (tx as unknown as { feeSource?: string }).feeSource : undefined;
  const feeXlm = stroopsToXlmAmount(BigInt(tx.fee));
  const memo = extractMemo(tx.memo);
  const validUntil = tx.timeBounds ? Number(tx.timeBounds.maxTime) : null;

  const operations: PreviewOperation[] = tx.operations.map((op, index) =>
    decodeOperation(op, index, sourceAccount)
  );

  const riskFlags: RiskFlag[] = [];
  for (const op of operations) {
    riskFlags.push(...assessOperation(op));
  }

  const intentComparison = compareAgainstIntent(operations, network, input.intent);
  if (!intentComparison.matches) {
    for (const mismatch of intentComparison.mismatches) {
      riskFlags.push({
        code: `INTENT_MISMATCH_${mismatch.field.toUpperCase()}`,
        severity: mismatch.severity,
        message: `Mismatch on ${mismatch.field}: expected ${mismatch.expected}, found ${mismatch.actual}`,
        operationIndex: mismatch.operationIndex,
      });
    }
  }

  const maxOpSeverity = maxSeverity(operations.map((o) => {
    const opFlags = riskFlags.filter((f) => f.operationIndex === o.index);
    return opFlags.length ? maxSeverity(opFlags.map((f) => f.severity)) : "info";
  }));
  const envelopeSeverity = maxSeverity(riskFlags.filter((f) => f.operationIndex === undefined).map((f) => f.severity));
  const overallSeverity = SEVERITY_ORDER[envelopeSeverity] > SEVERITY_ORDER[maxOpSeverity] ? envelopeSeverity : maxOpSeverity;

  let decision: PreviewDecision = "proceed";
  let decisionReason = "Transaction matches intent and passed safety checks.";

  if (overallSeverity === "critical" || intentComparison.mismatches.some((m) => m.severity === "critical")) {
    decision = "refuse";
    decisionReason = "Refused due to critical security or intent mismatch warnings.";
  } else if (overallSeverity === "high" || riskFlags.length > 0 || !intentComparison.matches) {
    decision = "confirm_with_warning";
    decisionReason = "Requires explicit confirmation due to high or medium risk warnings.";
  }

  const previewId = randomUUID();
  const transactionHash = computeSha256(input.xdr);
  const intentDigest = input.intent ? computeSha256(input.intent) : null;

  const audit = {
    previewId,
    generatedAt: new Date().toISOString(),
    transactionHash,
    intentDigest,
    previewDigest: "",
    requestId: input.auditContext?.requestId,
    userId: input.auditContext?.userId,
    channel: input.auditContext?.channel,
  };

  const previewWithoutDigest: TransactionPreview = {
    network,
    networkPassphrase: input.networkPassphrase,
    sourceAccount,
    isFeeBump,
    feeSource,
    feeXlm,
    memo,
    validUntil,
    operations,
    riskFlags,
    riskLevel: overallSeverity,
    intent: intentComparison,
    decision,
    decisionReason,
    audit,
  };

  audit.previewDigest = computeSha256(previewWithoutDigest);
  return previewWithoutDigest;
}
