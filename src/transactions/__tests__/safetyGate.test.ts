import { TransactionSafetyGate } from "../safetyGate";
import * as StellarSdk from "@stellar/stellar-sdk";

describe("TransactionSafetyGate", () => {
  it("approves a safe native payment transaction", async () => {
    const source = StellarSdk.Keypair.random();
    const dest = StellarSdk.Keypair.random();
    const builder = new StellarSdk.TransactionBuilder(source, {
      fee: "100",
      networkPassphrase: StellarSdk.Networks.TESTNET,
    });
    builder.addOperation(
      StellarSdk.Operation.payment({
        destination: dest.publicKey(),
        asset: StellarSdk.Asset.native(),
        amount: "10",
      })
    );
    builder.setTimeout(30);
    const tx = builder.build();
    const xdr = tx.toEnvelope().toXDR("base64");

    const gate = new TransactionSafetyGate({ maxAllowedSeverity: "high" });
    const result = await gate.evaluate(xdr);

    expect(result.approved).toBe(true);
    expect(result.reasons).toHaveLength(0);
  });

  it("rejects risky operations like account merge when exceeding severity threshold", async () => {
    const source = StellarSdk.Keypair.random();
    const dest = StellarSdk.Keypair.random();
    const builder = new StellarSdk.TransactionBuilder(source, {
      fee: "100",
      networkPassphrase: StellarSdk.Networks.TESTNET,
    });
    builder.addOperation(
      StellarSdk.Operation.accountMerge({
        destination: dest.publicKey(),
      })
    );
    builder.setTimeout(30);
    const tx = builder.build();
    const xdr = tx.toEnvelope().toXDR("base64");

    const gate = new TransactionSafetyGate({ maxAllowedSeverity: "medium" });
    const result = await gate.evaluate(xdr);

    expect(result.approved).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
    expect(result.diagnostics.maxSeverity).toBe("critical");
  });
});
