export type PreviewNetwork = "public" | "testnet" | "futurenet" | "unknown";

/**
 * What the caller must do with the preview:
 *  - proceed: normal confirmation prompt
 *  - confirm_with_warning: show warnings and require an explicit second confirmation
 *  - refuse: do not offer signing at all
 */
export type PreviewDecision = "proceed" | "confirm_with_warning" | "refuse";

export interface PreviewOperation {
  index: number;
  /** Stellar operation type, e.g. "payment", "setOptions". */
  type: string;
  /** One-line human-readable description. */
  summary: string;
  /** Account the operation acts on (operation source or transaction source). */
  sourceAccount: string;
  /** True when the operation acts on an account other than the transaction source. */
  foreignSource: boolean;
  /** True when the operation moves value out of the source account. */
  movesValue: boolean;
  asset?: string;
  amount?: string;
  destination?: string;
  /** Additional decoded fields relevant to this operation type. */
  details: Record<string, string | number | boolean | null>;
}

export interface TransactionIntent {
  /** Free-text description of what the user asked for (kept for the audit trail). */
  description?: string;
  /** Operation types the user's request is expected to produce. */
  operationTypes?: string[];
  /** Asset the user asked to move: "XLM", "USDC" or "USDC:G...". */
  asset?: string;
  /** Maximum amount the user asked to move, as a decimal string. */
  amount?: string;
  /** Destination account the user asked to send to. */
  destination?: string;
  network?: PreviewNetwork;
}

export interface IntentMismatch {
  field: IntentMismatchField;
  expected: string;
  actual: string;
  operationIndex?: number;
  severity: RiskSeverity;
}

export interface PreviewAuditTrail {
  previewId: string;
  generatedAt: string;
  /** Hash of the transaction as it will be signed (hex). */
  transactionHash: string;
  /** Hash of the normalized user intent; links the request to the preview. */
  intentDigest: string | null;
  /** Hash of the structured preview body; proves what the user was shown. */
  previewDigest: string;
  requestId?: string;
  userId?: string;
  channel?: string;
}

export interface BuildPreviewInput {
  /** Base64 transaction envelope XDR. */
  xdr: string;
  networkPassphrase: string;
  intent?: TransactionIntent;
  requestId?: string;
  userId?: string;
  channel?: string;
  /** Override clock for deterministic tests. */
  now?: Date;
}

export type RiskSeverity = "low" | "medium" | "high" | "critical";

export type DecisionAction = "proceed" | "confirm" | "refuse";

export interface RiskFlag {
  code: string;
  severity: RiskSeverity;
  message: string;
  operationIndex?: number;
}

export interface TransactionOperation {
  index: number;
  type: string;
  summary: string;
  sourceAccount: string;
  foreignSource: boolean;
  movesValue: boolean;
  asset: string;
  amount: string;
  destination?: string;
  details: Record<string, any>;
}

export interface IntentComparison {
  compared: boolean;
  matches: boolean;
  mismatches: string[];
}

export interface AuditInfo {
  previewId: string;
  generatedAt: string;
  transactionHash: string;
  intentDigest: string;
  previewDigest: string;
}

export interface TransactionPreview {
  network: string;
  networkPassphrase: string;
  sourceAccount: string;
  fee: string;
  feeXlm: string;
  sequence: string;
  memo: string | null;
  validUntil: string | null;
  isFeeBump: boolean;
  operations: TransactionOperation[];
  riskFlags: RiskFlag[];
  riskLevel: RiskSeverity;
  intent: IntentComparison;
  decision: DecisionAction;
  decisionReason: string;
  audit: AuditInfo;
}
