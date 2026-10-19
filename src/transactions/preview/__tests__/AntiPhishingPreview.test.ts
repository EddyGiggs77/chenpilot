import * as StellarSdk from "@stellar/stellar-sdk";
import { AntiPhishingPreview } from "../AntiPhishingPreview";

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

const payment = (destination = recipient, amount = "10") =>
  StellarSdk.Operation.payment({ destination, asset: StellarSdk.Asset.native(), amount });

describe("AntiPhishingPreview", () => {
  it("generates decoded preview and evaluates safety as safe for normal payment", () => {
    const xdr = buildXdr([payment()]);
    const preview = AntiPhishingPreview.generate({
      xdr,
      networkPassphrase: TESTNET,
      intent: { operationTypes: ["payment"], asset: "XLM", amount: "10", destination: recipient },
    });

    expect(preview.operations).toHaveLength(1);
    expect(preview.operations[0].type).toBe("payment");
    expect(preview.intent.matches).toBe(true);

    const safety = AntiPhishingPreview.evaluateSafety(preview);
    expect(safety.safe).toBe(true);
    expect(safety.requiresConfirmation).toBe(false);
    expect(safety.refused).toBe(false);
  });

  it("refuses transaction when intent destination does not match actual destination", () => {
    const xdr = buildXdr([payment(attacker)]);
    const preview = AntiPhishingPreview.generate({
      xdr,
      networkPassphrase: TESTNET,
      intent: { destination: recipient, amount: "10" },
    });

    expect(preview.intent.matches).toBe(false);
    expect(preview.decision).toBe("refuse");

    const safety = AntiPhishingPreview.evaluateSafety(preview);
    expect(safety.safe).toBe(false);
    expect(safety.refused).toBe(true);
  });
});
