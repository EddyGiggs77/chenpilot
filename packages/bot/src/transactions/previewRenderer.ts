import { TransactionPreview, renderPreviewText } from "../../src/transactions/preview";
import type { CommandReply } from "../commands/types";

export type PreviewDecision = "proceed" | "confirm_with_warning" | "refuse";

export interface BotPendingConfirmation {
  previewId: string;
  transactionHash: string;
  confirmationPhrase?: string;
}

export interface BotPreviewReply {
  reply: CommandReply;
  blocked: boolean;
  pending?: BotPendingConfirmation;
}

/**
 * Renders an anti-phishing transaction preview specifically for bot UX surfaces,
 * integrating risk warnings, confirmation requirements, and refusal flows.
 */
export function renderAntiPhishingPreview(preview: TransactionPreview): BotPreviewReply {
  const text = renderPreviewText(preview, { hideInfo: true });
  const base = { previewId: preview.audit.previewId, transactionHash: preview.audit.transactionHash };

  switch (preview.decision) {
    case "refuse":
      return {
        blocked: true,
        reply: {
          text: `⛔ TRANSACTION REFUSED DUE TO SECURITY RISK\n\n${text}`,
          ephemeral: true,
        },
      };

    case "confirm_with_warning": {
      const phrase = `CONFIRM ${preview.audit.transactionHash.slice(0, 6).toUpperCase()}`;
      return {
        blocked: false,
        pending: { ...base, confirmationPhrase: phrase },
        reply: {
          text: `${text}\n\n⚠️ HIGH RISK DETECTED. To approve this transaction, reply with:\n\`${phrase}\``,
        },
      };
    }

    case "proceed":
    default:
      return {
        blocked: false,
        reply: {
          text: `${text}\n\nReply 'APPROVE' or 'CONFIRM' to sign.`,
        },
      };
  }
}
