import * as StellarSdk from "@stellar/stellar-sdk";
import { TransactionPreview, BuildPreviewInput } from "./types";
import { buildTransactionPreview } from "./transactionPreview";

/**
 * Anti-phishing transaction preview generator and decoder.
 * Renders human-readable operation summaries, network/asset/address context,
 * risk warnings for high-impact or uncommon actions, structured comparison
 * to original user intent, and audit trail link.
 */
export class AntiPhishingPreview {
  /**
   * Builds and returns a fully decoded, human-safe transaction preview
   * with anti-phishing risk assessment and intent comparison.
   */
  public static generate(input: BuildPreviewInput): TransactionPreview {
    return buildTransactionPreview(input);
  }

  /**
   * Validates whether a transaction preview is safe to proceed or requires confirmation/refusal.
   */
  public static evaluateSafety(preview: TransactionPreview): {
    safe: boolean;
    requiresConfirmation: boolean;
    refused: boolean;
  } {
    return {
      safe: preview.decision === "proceed",
      requiresConfirmation: preview.decision === "confirm_with_warning",
      refused: preview.decision === "refuse",
    };
  }
}
