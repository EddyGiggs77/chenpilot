import { createHash } from "crypto";

export interface TransactionIntent {
  actionType: string;
  sender: string;
  recipient?: string;
  asset?: string;
  amount?: string;
  maxSlippagePercent?: number;
  route?: string[];
  expectedPrice?: string;
  chainStateTransition?: string;
  metadata?: Record<string, unknown>;
}

export interface PreflightParams {
  estimatedGasStroops?: number;
  maxGasStroops?: number;
  requiresApproval?: boolean;
  approvalGranted?: boolean;
  chainCompatibility?: boolean;
  currentBalance?: string;
  requiredBalance?: string;
}

export interface SafetyThresholds {
  maxAllowedSlippagePercent: number;
  maxAllowedGasStroops: number;
  requireExplicitApproval: boolean;
  enforceChainCompatibility: boolean;
}

export const DEFAULT_SAFETY_THRESHOLDS: SafetyThresholds = {
  maxAllowedSlippagePercent: 5.0,
  maxAllowedGasStroops: 100_000_000,
  requireExplicitApproval: true,
  enforceChainCompatibility: true,
};

export interface SafetyViolation {
  code: string;
  message: string;
  severity: "low" | "medium" | "high" | "critical";
}

export interface SafetyEvidence {
  evaluatorVersion: string;
  evaluatedAt: string;
  intentHash: string;
  violations: SafetyViolation[];
  passed: boolean;
  diagnostics: Record<string, unknown>;
}

export interface SafetyEvaluationResult {
  allowed: boolean;
  violations: SafetyViolation[];
  evidence: SafetyEvidence;
}

export class TransactionSafetyEngine {
  private thresholds: SafetyThresholds;

  constructor(thresholds: Partial<SafetyThresholds> = {}) {
    this.thresholds = { ...DEFAULT_SAFETY_THRESHOLDS, ...thresholds };
  }

  public updateThresholds(newThresholds: Partial<SafetyThresholds>): void {
    this.thresholds = { ...this.thresholds, ...newThresholds };
  }

  public getThresholds(): SafetyThresholds {
    return { ...this.thresholds };
  }

  public validateTransactionIntent(intent: TransactionIntent): SafetyViolation[] {
    const violations: SafetyViolation[] = [];

    if (!intent.actionType || typeof intent.actionType !== "string") {
      violations.push({
        code: "INVALID_ACTION_TYPE",
        message: "Transaction intent must specify a valid actionType.",
        severity: "critical",
      });
    }

    if (!intent.sender || typeof intent.sender !== "string") {
      violations.push({
        code: "INVALID_SENDER",
        message: "Transaction intent must specify a valid sender address.",
        severity: "critical",
      });
    }

    if (intent.maxSlippagePercent !== undefined) {
      if (
        typeof intent.maxSlippagePercent !== "number" ||
        isNaN(intent.maxSlippagePercent) ||
        intent.maxSlippagePercent < 0
      ) {
        violations.push({
          code: "INVALID_SLIPPAGE_PARAMETER",
          message: "maxSlippagePercent must be a non-negative number.",
          severity: "high",
        });
      } else if (intent.maxSlippagePercent > this.thresholds.maxAllowedSlippagePercent) {
        violations.push({
          code: "EXCESSIVE_SLIPPAGE",
          message: `Specified slippage (${intent.maxSlippagePercent}%) exceeds maximum allowed threshold (${this.thresholds.maxAllowedSlippagePercent}%).`,
          severity: "high",
        });
      }
    }

    if (intent.amount !== undefined) {
      const parsedAmount = Number(intent.amount);
      if (isNaN(parsedAmount) || parsedAmount < 0) {
        violations.push({
          code: "INVALID_AMOUNT",
          message: "Transaction amount must be a valid non-negative number string.",
          severity: "critical",
        });
      }
    }

    return violations;
  }

  public evaluatePreflightChecks(intent: TransactionIntent, preflight: PreflightParams): SafetyViolation[] {
    const violations: SafetyViolation[] = [];

    if (preflight.chainCompatibility === false && this.thresholds.enforceChainCompatibility) {
      violations.push({
        code: "CHAIN_COMPATIBILITY_FAILURE",
        message: "Target chain state transition or protocol is incompatible with the current network state.",
        severity: "critical",
      });
    }

    if (preflight.estimatedGasStroops !== undefined && preflight.estimatedGasStroops > this.thresholds.maxAllowedGasStroops) {
      violations.push({
        code: "EXCESSIVE_GAS",
        message: `Estimated gas (${preflight.estimatedGasStroops} stroops) exceeds max allowed limit (${this.thresholds.maxAllowedGasStroops} stroops).`,
        severity: "high",
      });
    }

    if (preflight.requiresApproval && this.thresholds.requireExplicitApproval && !preflight.approvalGranted) {
      violations.push({
        code: "MISSING_APPROVAL",
        message: "Transaction requires explicit approval before execution, but none was granted.",
        severity: "critical",
      });
    }

    if (preflight.currentBalance !== undefined && preflight.requiredBalance !== undefined) {
      const current = Number(preflight.currentBalance);
      const required = Number(preflight.requiredBalance);
      if (!isNaN(current) && !isNaN(required) && current < required) {
        violations.push({
          code: "INSUFFICIENT_BALANCE_PREFLIGHT",
          message: `Current balance (${current}) is insufficient for required amount (${required}).`,
          severity: "critical",
        });
      }
    }

    return violations;
  }

  public evaluate(intent: TransactionIntent, preflight: PreflightParams = {}): SafetyEvaluationResult {
    const intentViolations = this.validateTransactionIntent(intent);
    const preflightViolations = this.evaluatePreflightChecks(intent, preflight);
    const allViolations = [...intentViolations, ...preflightViolations];

    const passed = allViolations.filter((v) => v.severity === "high" || v.severity === "critical").length === 0;

    const serializedIntent = JSON.stringify(intent);
    const intentHash = createHash("sha256").update(serializedIntent).digest("hex");

    const evidence: SafetyEvidence = {
      evaluatorVersion: "1.0.0",
      evaluatedAt: new Date().toISOString(),
      intentHash,
      violations: allViolations,
      passed,
      diagnostics: {
        thresholdsUsed: this.thresholds,
        intent,
        preflight,
      },
    };

    return {
      allowed: passed,
      violations: allViolations,
      evidence,
    };
  }
}

export const transactionSafetyEngine = new TransactionSafetyEngine();
