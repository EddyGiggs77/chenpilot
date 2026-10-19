import { buildTransactionPreview, TransactionIntent } from "./preview";
import { RiskSeverity } from "./preview/types";
import { AuditAction, AuditSeverity } from "../AuditLog/auditLog.entity";
import { auditLogService } from "../AuditLog/auditLog.service";
import logger from "../config/logger";

export interface SafetyGateOptions {
  maxAllowedSeverity?: RiskSeverity;
  requireIntentMatch?: boolean;
  allowedOperations?: string[];
  networkPassphrase?: string;
}

export interface SafetyEvaluationResult {
  approved: boolean;
  reasons: string[];
  diagnostics: {
    maxSeverity: RiskSeverity;
    riskCodes: string[];
    operationCount: number;
    evidenceId?: string;
  };
  preview?: any;
}

const SEVERITY_RANK: Record<RiskSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export class TransactionSafetyGate {
  constructor(private readonly defaultOptions: SafetyGateOptions = {}) {}

  async evaluate(envelopeXdr: string, intent?: TransactionIntent, options: SafetyGateOptions = {}):
    Promise<SafetyEvaluationResult> {
    const netPassphrase = options.networkPassphrase ?? this.defaultOptions.networkPassphrase;
    const preview = buildTransactionPreview({
      xdr: envelopeXdr,
      networkPassphrase: netPassphrase,
      intent,
    });

    const reasons: string[] = [];
    const riskCodes: string[] = [];
    let maxSev: RiskSeverity = "info";

    for (const flag of preview.riskFlags) {
      riskCodes.push(flag.code);
      if (SEVERITY_RANK[flag.severity] > SEVERITY_RANK[maxSev]) {
        maxSev = flag.severity;
      }
    }

    const maxAllowed = options.maxAllowedSeverity ?? this.defaultOptions.maxAllowedSeverity ?? "high";

    if (preview.decision === "refuse") {
      reasons.push("Transaction preview explicitly refused due to critical risk flags.");
    }

    if (SEVERITY_RANK[maxSev] >= SEVERITY_RANK[maxAllowed]) {
      reasons.push(`Transaction risk severity '${maxSev}' exceeds or meets maximum allowed threshold '${maxAllowed}'.`);
    }

    const allowedOps = options.allowedOperations ?? this.defaultOptions.allowedOperations;
    if (allowedOps && allowedOps.length > 0) {
      for (const op of preview.operations) {
        if (!allowedOps.includes(op.type)) {
          reasons.push(`Operation type '${op.type}' is not permitted by policy.`);
        }
      }
    }

    if (preview.intentComparison && !preview.intentComparison.matches) {
      reasons.push("Transaction operations do not match stated user intent.");
    }

    const approved = reasons.length === 0;
    let evidenceId: string | undefined;

    try {
      const auditRecord = await auditLogService.logEvent({
        action: approved ? AuditAction.TRANSACTION_SUBMITTED : AuditAction.TRANSACTION_REJECTED,
        severity: approved ? AuditSeverity.INFO : AuditSeverity.WARNING,
        details: {
          approved,
          reasons,
          diagnostics: {
            maxSeverity: maxSev,
            riskCodes,
            operationCount: preview.operations.length,
          },
          intent,
        },
      });
      evidenceId = auditRecord?.id;
    } catch (err) {
      logger.error("Failed to capture safety gate evidence bundle in audit log:", err);
    }

    if (!approved) {
      logger.warn("Transaction safety gate rejected transaction", {
        reasons,
        maxSeverity: maxSev,
        riskCodes,
      });
    }

    return {
      approved,
      reasons,
      diagnostics: {
        maxSeverity: maxSev,
        riskCodes,
        operationCount: preview.operations.length,
        evidenceId,
      },
      preview,
    };
  }
}

export const transactionSafetyGate = new TransactionSafetyGate();
