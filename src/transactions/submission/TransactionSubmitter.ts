import logger from "../../config/logger";
import { transactionSafetyEngine, TransactionIntent, PreflightParams, SafetyEvaluationResult } from "../../Execution/TransactionSafetyEngine";
import { SubmissionGateway, SubmitOutcome } from "./SubmissionGateway";

export interface SubmissionRequest {
  envelopeXdr: string;
  intent: TransactionIntent;
  preflight?: PreflightParams;
}

export interface SafeSubmitResult {
  success: boolean;
  outcome?: SubmitOutcome;
  evaluation: SafetyEvaluationResult;
  error?: string;
}

export class TransactionSubmitter {
  constructor(private readonly gateway?: SubmissionGateway) {}

  public async submitSafely(request: SubmissionRequest): Promise<SafeSubmitResult> {
    const preflight = request.preflight || {};
    const evaluation = transactionSafetyEngine.evaluate(request.intent, preflight);

    if (!evaluation.allowed) {
      logger.warn("Transaction submission blocked by safety engine", {
        intent: request.intent,
        violations: evaluation.violations,
        evidence: evaluation.evidence,
      });
      return {
        success: false,
        evaluation,
        error: `Submission blocked by safety engine: ${evaluation.violations.map((v) => v.message).join("; ")}`,
      };
    }

    if (!this.gateway) {
      return {
        success: true,
        evaluation,
        error: "No submission gateway configured; safety gate passed successfully.",
      };
    }

    try {
      const outcome = await this.gateway.submit(request.envelopeXdr);
      return {
        success: outcome.status === "applied" || outcome.status === "accepted",
        outcome,
        evaluation,
      };
    } catch (err) {
      logger.error("Error during gateway transaction submission", { error: err });
      throw err;
    }
  }
}
