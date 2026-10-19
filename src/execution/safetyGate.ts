export interface TransactionIntent {
  chainId: number;
  to: string;
  value: string;
  data: string;
  gasLimit?: string;
  maxSlippagePercent?: number;
  approvalAmount?: string;
  routeSteps?: number;
  priceImpactPercent?: number;
  isVerifiedContract?: boolean;
}

export interface SafetyEvaluationResult {
  approved: boolean;
  reasons: string[];
  diagnostics: Record<string, any>;
  evidenceId: string;
}

export interface RiskThresholds {
  maxSlippagePercent: number;
  maxPriceImpactPercent: number;
  maxApprovalAmount: string;
  requireVerifiedContract: boolean;
  maxRouteSteps: number;
}

export class TransactionSafetyGate {
  private thresholds: RiskThresholds;

  constructor(thresholds?: Partial<RiskThresholds>) {
    this.thresholds = {
      maxSlippagePercent: 1.0,
      maxPriceImpactPercent: 3.0,
      maxApprovalAmount: "1000000000000000000000",
      requireVerifiedContract: true,
      maxRouteSteps: 4,
      ...(thresholds || {})
    };
  }

  public updateThresholds(newThresholds: Partial<RiskThresholds>): void {
    this.thresholds = { ...this.thresholds, ...newThresholds };
  }

  public getThresholds(): RiskThresholds {
    return { ...this.thresholds };
  }

  public evaluate(intent: TransactionIntent): SafetyEvaluationResult {
    const reasons: string[] = [];
    const diagnostics: Record<string, any> = {};
    const evidenceId = "ev-" + Math.random().toString(36).substring(2, 11) + "-" + Date.now();

    if (intent.maxSlippagePercent !== undefined && intent.maxSlippagePercent > this.thresholds.maxSlippagePercent) {
      reasons.push(`Slippage ${intent.maxSlippagePercent}% exceeds maximum allowed ${this.thresholds.maxSlippagePercent}%`);
      diagnostics["slippage"] = intent.maxSlippagePercent;
    }

    if (intent.priceImpactPercent !== undefined && intent.priceImpactPercent > this.thresholds.maxPriceImpactPercent) {
      reasons.push(`Price impact ${intent.priceImpactPercent}% exceeds maximum allowed ${this.thresholds.maxPriceImpactPercent}%`);
      diagnostics["priceImpact"] = intent.priceImpactPercent;
    }

    if (intent.routeSteps !== undefined && intent.routeSteps > this.thresholds.maxRouteSteps) {
      reasons.push(`Route steps ${intent.routeSteps} exceed maximum allowed ${this.thresholds.maxRouteSteps}`);
      diagnostics["routeSteps"] = intent.routeSteps;
    }

    if (this.thresholds.requireVerifiedContract && intent.isVerifiedContract === false) {
      reasons.push("Target contract is not verified");
      diagnostics["isVerifiedContract"] = false;
    }

    if (!intent.to || intent.to.trim() === "") {
      reasons.push("Invalid or missing recipient address");
      diagnostics["to"] = intent.to;
    }

    const approved = reasons.length === 0;
    diagnostics["evaluatedAt"] = new Date().toISOString();
    diagnostics["intent"] = intent;

    return {
      approved,
      reasons,
      diagnostics,
      evidenceId
    };
  }
}

export const globalSafetyGate = new TransactionSafetyGate();
