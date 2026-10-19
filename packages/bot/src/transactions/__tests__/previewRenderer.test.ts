import { describe, it, expect } from "@jest/globals";
import { renderAntiPhishingPreview } from "../previewRenderer";
import { TransactionPreview } from "../../../../src/transactions/preview";

describe("previewRenderer", () => {
  const basePreview: TransactionPreview = {
    network: "testnet",
    networkPassphrase: "Test SDF Network ; September 2015",
    sourceAccount: "GA........................................................",
    isFeeBump: false,
    feeXlm: "0.01",
    memo: null,
    validUntil: null,
    operations: [
      {
        index: 0,
        type: "payment",
        summary: "Send 10 XLM to GB...",
        sourceAccount: "GA...",
        foreignSource: false,
        movesValue: true,
        details: {},
      },
    ],
    riskFlags: [],
    riskLevel: "info",
    intent: { compared: false, matches: true, mismatches: [] },
    decision: "proceed",
    decisionReason: "Safe",
    audit: {
      previewId: "prev-123",
      generatedAt: new Date().toISOString(),
      transactionHash: "abcdef1234567890",
      intentDigest: null,
      previewDigest: "digest-123",
    },
  };

  it("renders a proceed preview correctly", () => {
    const res = renderAntiPhishingPreview(basePreview);
    expect(res.blocked).toBe(false);
    expect(res.pending).toBeUndefined();
    expect(res.reply.text).toContain("Transaction preview");
    expect(res.reply.text).toContain("APPROVE");
  });

  it("renders confirm_with_warning with confirmation phrase", () => {
    const warningPreview: TransactionPreview = {
      ...basePreview,
      decision: "confirm_with_warning",
      riskLevel: "high",
    };
    const res = renderAntiPhishingPreview(warningPreview);
    expect(res.blocked).toBe(false);
    expect(res.pending).toBeDefined();
    expect(res.pending?.confirmationPhrase).toBe("CONFIRM ABCDEF");
    expect(res.reply.text).toContain("CONFIRM ABCDEF");
  });

  it("renders refusal flow and blocks signing", () => {
    const refusePreview: TransactionPreview = {
      ...basePreview,
      decision: "refuse",
      riskLevel: "critical",
    };
    const res = renderAntiPhishingPreview(refusePreview);
    expect(res.blocked).toBe(true);
    expect(res.reply.ephemeral).toBe(true);
    expect(res.reply.text).toContain("TRANSACTION REFUSED");
  });
});
