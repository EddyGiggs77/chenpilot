import { createHash, randomUUID } from "crypto";
import * as StellarSdk from "@stellar/stellar-sdk";
import { SafeXdrDecoder } from "../../utils/xdr";
import { decodeOperation } from "./operationDecoder";
import { assessEnvelope, assessOperation, maxSeverity, SEVERITY_ORDER } from "./riskAssessment";
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

// Passphrases are fixed by the Stellar protocol.
const NETWORK_PASSPHRASES: Record<string, PreviewNetwork> = {
  "Public Global Stellar Network ; September 2015": "public",
  "Test SDF Network ; September 2015": "testnet",
  "Test SDF Future Network ; October 2022": "futurenet",
};

export function detectNetwork(passphrase: string): PreviewNetwork {
  return NETWORK_PASSPHRASES[passphrase] ?? "unknown";
}

const STROOPS_PER_UNIT = BigInt(10_000_000);

/** Parses a Stellar decimal amount ("12.5") into stroops without floating-point loss. */
export function toStroops(amount: string): bigint {
  const trimmed = amount.trim();
  if (!/^\d+(\.\d{1,7})?$/.test(trimmed)) {
    throw new Error(`Invalid amount: ${amount}`);
  }
  const [whole, fraction = ""] = trimmed.split(".");
  return BigInt(whole) * STROOPS_PER_UNIT + BigInt(fraction.padEnd(7, "0"));
}

function stroopsToXlm(stroops: bigint): string {
  const whole = stroops / STROOPS_PER_UNIT;
  const fraction = (stroops % STROOPS_PER_UNIT).toString().padStart(7, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((k) => record[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(record[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: unknown): string {
  return createHash("sha256").update(stableStringify(value)).digest("hex");
}

function describeMemo(memo: StellarSdk.Memo): string | null {
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

/** "USDC" matches any USDC issuer; "USDC:G..." must match exactly. */
function assetMatches(expected: string, actual: string): boolean {
  const norm = (a: string) => (a.toUpperCase() === "NATIVE" ? "XLM" : a.toUpperCase());
  const e = norm(expected);
  const a = norm(actual);
  return e.includes(":") ? e === a : e === a.split(":")[0];
}

export function compareToIntent(
  operations: PreviewOperation[],
  network: PreviewNetwork,
  intent?: TransactionIntent
): IntentComparison {
  if (!intent) return { compared: false, matches: true, mismatches: [] };

  const mismatches: IntentMismatch[] = [];

  if (intent.network && intent.network !== network) {
    mismatches.push({ field: "network", expected: intent.network, actual: network, severity: "critical" });
  }

  if (intent.operationTypes?.length) {
    for (const op of operations) {
      if (!intent.operationTypes.includes(op.type)) {
        mismatches.push({
          field: "operationType",
          expected: intent.operationTypes.join(", "),
          actual: op.type,
          operationIndex: op.index,
          severity: "high",
        });
      }
    }
  }

  const valueOps = operations.filter((op) => op.movesValue);
  let totalMoved = BigInt(0);

  for (const op of valueOps) {
    if (intent.destination && op.destination && op.destination !== intent.destination) {
      mismatches.push({
        field: "destination",
        expected: intent.destination,
        actual: op.destination,
        operationIndex: op.index,
        severity: "critical",
      });
    }
    if (intent.asset && op.asset && !assetMatches(intent.asset, op.asset)) {
      mismatches.push({ field: "asset", expected: intent.asset, actual: op.asset, operationIndex: op.index, severity: "high" });
    }
    if (op.amount) {
      try {
        totalMoved += toStroops(op.amount);
      } catch {
        // Undecodable amounts are surfaced by the operation summary itself.
      }
    }
  }

  if (intent.amount && valueOps.length > 0) {
    const expected = toStroops(intent.amount);
    if (totalMoved > expected) {
      mismatches.push({
        field: "amount",
        expected: intent.amount,
        actual: stroopsToXlm(totalMoved),
        severity: "high",
      });
    }
  }

  return { compared: true, matches: mismatches.length === 0, mismatches };
}

export function decide(
  operations: PreviewOperation[],
  flags: RiskFlag[],
  comparison: IntentComparison,
  intent?: TransactionIntent
): { decision: PreviewDecision; reason: string } {
  const declared = new Set(intent?.operationTypes ?? []);

  const undeclaredCritical = flags.filter(
    (f) =>
      f.severity === "critical" &&
      (f.operationIndex === undefined || !declared.has(operations[f.operationIndex]?.type))
  );
  if (undeclaredCritical.length) {
    return { decision: "refuse", reason: undeclaredCritical[0].message };
  }

  const criticalMismatch = comparison.mismatches.find((m) => m.severity === "critical");
  if (criticalMismatch) {
    return {
      decision: "refuse",
      reason: `The transaction's ${criticalMismatch.field} (${criticalMismatch.actual}) does not match your request (${criticalMismatch.expected}).`,
    };
  }

  if (comparison.mismatches.length) {
    return { decision: "confirm_with_warning", reason: "The transaction differs from what you asked for." };
  }

  const elevated = flags.filter((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.high);
  if (elevated.length) {
    return { decision: "confirm_with_warning", reason: elevated[0].message };
  }

  return { decision: "proceed", reason: "No high-risk actions detected." };
}

export function buildTransactionPreview(input: BuildPreviewInput): TransactionPreview {
  const decoded = SafeXdrDecoder.decodeTransaction(input.xdr, input.networkPassphrase);
  const network = detectNetwork(input.networkPassphrase);
  const sourceAccount = decoded.source;
  const feeStroops = BigInt(decoded.fee);
  const feeXlm = stroopsToXlm(feeStroops);
  const sequence = decoded.sequenceNumber;
  const memo = decoded.memo ? describeMemo(decoded.memo) : null;
  const validUntil = decoded.timeBounds ? new Date(Number(decoded.timeBounds.maxTime) * 1000).toISOString() : null;
  const isFeeBump = decoded.feeBump ?? false;
  const feeSource = decoded.feeSource;

  const operations = decoded.operations.map((op, index) => decodeOperation(op, index, sourceAccount));
  const comparison = compareToIntent(operations, network, input.intent);

  const riskFlags: RiskFlag[] = [
    ...assessEnvelope({ network, feeStroops, operationCount: operations.length, validUntil }),
    ...operations.flatMap(assessOperation),
  ];

  if (input.intent?.operationTypes) {
    const declared = new Set(input.intent.operationTypes);
    for (const op of operations) {
      if (!declared.has(op.type)) {
        riskFlags.push({
          code: 'INTENT_OPERATIONTYPE_MISMATCH',
          severity: 'high',
          message: `Operation ${op.index + 1} type "${op.type}" was not requested.`,
          operationIndex: op.index,
        });
      }
    }
  }

  if (!comparison.matches && comparison.compared) {
    for (const m of comparison.mismatches) {
      riskFlags.push({
        code: `INTENT_MISMATCH_${m.field.toUpperCase()}`,
        severity: m.severity,
        message: `Mismatch on ${m.field}: expected ${m.expected}, got ${m.actual}.`,
        operationIndex: m.operationIndex,
      });
    }
  }

  const severities = riskFlags.map((f) => f.severity);
  const riskLevel = severities.length ? maxSeverity(severities) : 'info';
  const { decision, reason } = decide(operations, riskFlags, comparison, input.intent);

  const auditTrailDigestInput = { sourceAccount, operations: operations.map(o => o.summary), fee: decoded.fee, memo };
  const previewDigest = sha256(auditTrailDigestInput);
  const intentDigest = input.intent ? sha256(input.intent) : null;
  const previewId = randomUUID();
  const transactionHash = sha256(input.xdr);

  return {
    network,
    networkPassphrase: input.networkPassphrase,
    sourceAccount,
    fee: decoded.fee,
    feeXlm,
    sequence,
    memo,
    validUntil,
    isFeeBump,
    feeSource,
    operations,
    riskFlags,
    riskLevel,
    intent: comparison,
    decision,
    decisionReason: reason,
    audit: {
      previewId,
      generatedAt: (input.now ?? new Date()).toISOString(),
      transactionHash,
      intentDigest,
      previewDigest,
      requestId: input.requestId,
      userId: input.userId,
      channel: input.channel,
    },
  };
}

/**
 * Decodes a transaction envelope into a structured, human-safe preview.
 * Throws an XDR error (from SafeXdrDecoder) when the payload cannot be decoded;
 * callers must treat that as a refusal, never fall back to an opaque prompt.
 */
export function buildTransactionPreview(input: BuildPreviewInput): TransactionPreview {
  const decoded = SafeXdrDecoder.decodeTransaction(input.xdr, {
    networkPassphrase: input.networkPassphrase,
  });

  const isFeeBump = decoded instanceof StellarSdk.FeeBumpTransaction;
  const tx = isFeeBump
    ? (decoded as StellarSdk.FeeBumpTransaction).innerTransaction
    : (decoded as StellarSdk.Transaction);

  const network = detectNetwork(input.networkPassphrase);
  const feeStroops = BigInt(decoded.fee);
  const maxTime = tx.timeBounds?.maxTime;
  const validUntil = maxTime && maxTime !== "0" ? new Date(Number(maxTime) * 1000).toISOString() : null;

  const operations = tx.operations.map((op, i) => decodeOperation(op, i, tx.source));

  const riskFlags = [
    ...assessEnvelope({ network, feeStroops, operationCount: operations.length, validUntil }),
    ...operations.flatMap(assessOperation),
  ];

  const intent = compareToIntent(operations, network, input.intent);
  for (const m of intent.mismatches) {
    riskFlags.push({
      code: `INTENT_${m.field.toUpperCase()}_MISMATCH`,
      severity: m.severity,
      message: `Expected ${m.field} "${m.expected}" but the transaction has "${m.actual}".`,
      operationIndex: m.operationIndex,
    });
  }

  const { decision, reason } = decide(operations, riskFlags, intent, input.intent);

  const body = {
    network,
    networkPassphrase: input.networkPassphrase,
    sourceAccount: tx.source,
    fee: feeStroops.toString(),
    feeXlm: stroopsToXlm(feeStroops),
    sequence: tx.sequence,
    memo: describeMemo(tx.memo),
    validUntil,
    isFeeBump,
    feeSource: isFeeBump ? (decoded as StellarSdk.FeeBumpTransaction).feeSource : undefined,
    operations,
    riskFlags,
    riskLevel: maxSeverity(riskFlags.map((f) => f.severity)),
    intent,
    decision,
    decisionReason: reason,
  };

  return {
    ...body,
    audit: {
      previewId: randomUUID(),
      generatedAt: (input.now ?? new Date()).toISOString(),
      transactionHash: decoded.hash().toString("hex"),
      intentDigest: input.intent ? sha256(input.intent) : null,
      previewDigest: sha256(body),
      requestId: input.requestId,
      userId: input.userId,
      channel: input.channel,
    },
  };
}
