import logger from "../config/logger";
import { transactionSafetyEngine, TransactionIntent, PreflightParams, SafetyEvaluationResult } from "./TransactionSafetyEngine";

export interface ExecutionRequest {
  intent: TransactionIntent;
  preflight?: PreflightParams;
  envelopeXdr?: string;
}

export interface ExecutionResult {
  success: boolean;
  txHash?: string;
  evaluation: SafetyEvaluationResult;
  error?: string;
}

export class ExecutionEngine {
  public async execute(request: ExecutionRequest): Promise<ExecutionResult> {
    const preflight = request.preflight || {};
    const evaluation = transactionSafetyEngine.evaluate(request.intent, preflight);

    if (!evaluation.allowed) {
      logger.warn("Transaction execution rejected by safety engine", {
        intent: request.intent,
        violations: evaluation.violations,
        evidence: evaluation.evidence,
      });
      return {
        success: false,
        evaluation,
        error: `Transaction rejected by safety engine: ${evaluation.violations.map((v) => v.message).join("; ")}`,
      };
    }

    logger.info("Transaction safety evaluation passed", {
      intentHash: evaluation.evidence.intentHash,
    });

    // Proceed with simulated or actual execution pipeline if allowed
    return {
      success: true,
      txHash: "simulated-tx-hash-" + evaluation.evidence.intentHash.substring(0, 16),
      evaluation,
    };
  }
}

export const executionEngine = new ExecutionEngine();
