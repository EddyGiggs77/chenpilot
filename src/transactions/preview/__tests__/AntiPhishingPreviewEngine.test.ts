import * as StellarSdk from "@stellar/stellar-sdk";
import { AntiPhishingPreviewEngine } from "../AntiPhishingPreviewEngine";
import { PreviewAuditSink } from "../previewAudit";

const TESTNET = StellarSdk.Networks.TESTNET;
const source = StellarSdk.Keypair.random();
const recipient = StellarSdk.Keypair.random().publicKey();
const attacker = StellarSdk.Keypair.random().publicKey();

function buildXdr(ops: StellarSdk.xdr.Operation[]): string {
  const account = new StellarSdk.Account(source.publicKey(), "100");
  const builder = new StellarSdk.TransactionBuilder(account, {
    fee: "100",
    networkPassphrase: TESTNET,
  });
  ops.forEach((op) => builder.addOperation(op));
  builder.setTimeout(300);
  return builder.build().toXDR();
}

describe("AntiPhishingPreviewEngine", () => {
  it("generates a structured preview and renders text safely", async () => {
    const xdr = buildXdr([StellarSdk.Operation.payment({
      destination: recipient,
      asset: StellarSdk.Asset.native(),
      amount: "50",
    })]);

    const auditSink: PreviewAuditSink = {
      logEvent: jest.fn(async () => ({})),
    };

    const engine = new AntiPhishingPreviewEngine(auditSink);
    const preview = await engine.generatePreview(
      {
        xdr,
        networkPassphrase: TESTNET,
        intent: { asset: "XLM", amount: "50", destination: recipient },
      },
      "bot",
      "user-123"
    );

    expect(preview.network).toBe("testnet");
    expect(preview.decision).toBe("proceed");
    expect(auditSink.logEvent).toHaveBeenCalledTimes(1);

    const text = engine.renderText(preview);
    expect(text).toContain("Transaction preview");
    expect(text).toContain("Stellar Testnet");
    expect(text).toContain("Send 50.0000000 XLM");
  });

  it("refuses transaction and invokes audit logging on intent mismatch", async () => {
    const xdr = buildXdr([StellarSdk.Operation.payment({
      destination: attacker,
      asset: StellarSdk.Asset.native(),
      amount: "50",
    })]);

    const auditSink: PreviewAuditSink = {
      logEvent: jest.fn(async () => ({})),
    };

    const engine = new AntiPhishingPreviewEngine(auditSink);
    const preview = await engine.generatePreview({
      xdr,
      networkPassphrase: TESTNET,
      intent: { destination: recipient, amount: "50" },
    });

    expect(preview.decision).toBe("refuse");
    expect(auditSink.logEvent).toHaveBeenCalled();

    const text = engine.renderText(preview);
    expect(text).toContain("TRANSACTION BLOCKED");
  });
});
