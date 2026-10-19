import * as StellarSdk from "@stellar/stellar-sdk";
import { TransactionPreview, TransactionIntent, BuildPreviewInput } from "./types";
import { buildTransactionPreview } from "./transactionPreview";
import { recordPreviewAudit, PreviewAuditSink } from "./previewAudit";
import { renderPreviewText, RenderOptions } from "./renderPreview";

/**
 * Anti-phishing transaction preview engine wrapping decoding, risk assessment,
 * intent comparison, text rendering, and audit logging into a single cohesive gateway.
 */
export class AntiPhishingPreviewEngine {
  constructor(private readonly auditSink?: PreviewAuditSink) {}

  /**
   * Decodes a transaction raw XDR payload, assesses risks, compares against user intent,
   * and optionally logs to the audit sink.
   */
  public async generatePreview(input: BuildPreviewInput, channel = "bot", userId?: string): Promise<TransactionPreview> {
    const preview = buildTransactionPreview(input);

    if (this.auditSink) {
      // Attach audit channel and userId if supplied
      preview.audit.channel = channel;
      preview.audit.userId = userId;
      await recordPreviewAudit(preview, this.auditSink);
    }

    return preview;
  }

  /**
   * Renders a human-safe preview text suitable for display in chat bots and UIs.
   */
  public renderText(preview: TransactionPreview, options: RenderOptions = {}): string {
    return renderPreviewText(preview, options);
  }
}
