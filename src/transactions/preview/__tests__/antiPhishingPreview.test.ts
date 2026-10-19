import { describe, it, expect } from "@jest/globals";
import { renderPreviewText, severityLabel, sanitizeForDisplay } from "../renderPreview";
import { TransactionPreview } from "../types";

describe("Anti-phishing transaction previews", () => {
  it("sanitizes unsafe unicode characters correctly", () => {
    const malicious = "USDC\u202eG123456789";
    const sanitized = sanitizeForDisplay(malicious);
    expect(sanitized).not.toContain("\u202e");
    expect(sanitized).toContain("\ufffd");
  });

  it("renders correct severity labels", () => {
    expect(severityLabel("critical")).toContain("CRITICAL");
    expect(severityLabel("high")).toContain("HIGH");
    expect(severityLabel("medium")).toContain("Medium");
  });

  it("renders high-risk warning preview headers correctly", () => {
    const preview: TransactionPreview = {
      network: "public",
      networkPassphrase: "Public Global Stellar Network ; September 2015",
      sourceAccount: "GA33333333333333333333333333333333333333333333333333",
      fee: "100000",
      feeXlm: "0.01",
      sequence: "12345",
      memo: null,
      validUntil: null,
      isFeeBump: false,
      operations: [
        {
          index: 0,
          type: "accountMerge",
          summary: "CLOSE account and transfer all funds",
          sourceAccount: "GA33333333333333333333333333333333333333333333333333",
          foreignSource: false,
          movesValue: true,
          asset: "XLM",
          amount: "100",
          destination: "GB44444444444444444444444444444444444444444444444444",
          details: {},
        },
      ],
      riskFlags: [
        {
          code: "ACCOUNT_MERGE",
          severity: "critical",
          message: "This closes the account and transfers ALL of its XLM. This cannot be undone.",
          operationIndex: 0,
        },
      ],
      riskLevel: "critical",
      intent: { compared: true, matches: false, mismatches: [] },
      decision: "refuse",
      decisionReason: "Critical risk detected",
      audit: {
        previewId: "preview-123",
        generatedAt: "2025-01-01T00:00:00.000Z",
        transactionHash: "abc123hash",
        intentDigest: "intent-digest",
        previewDigest: "preview-digest",
      },
    };

    const text = renderPreviewText(preview);
    expect(text).toContain("⛔ TRANSACTION BLOCKED");
    expect(text.toLowerCase()).toContain("critical");
    expect(text).toContain("Stellar Mainnet (real funds)");
  });
});
