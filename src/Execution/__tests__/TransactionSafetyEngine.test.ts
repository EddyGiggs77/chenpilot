import { TransactionSafetyEngine, TransactionIntent, PreflightParams } from "../TransactionSafetyEngine";
import { executionEngine } from "../ExecutionEngine";
import { TransactionSubmitter } from "../../transactions/submission/TransactionSubmitter";
import { describe, it, expect } from "@jest/globals";

describe("TransactionSafetyEngine and Safety Gates", () => {
  const engine = new TransactionSafetyEngine({
    maxAllowedSlippagePercent: 5.0,
    maxAllowedGasStroops: 10_000_000,
    requireExplicitApproval: true,
    enforceChainCompatibility: true,
  });

  const validIntent: TransactionIntent = {
    actionType: "swap",
    sender: "GAB...",
    recipient: "GCD...",
    asset: "USDC",
    amount: "100.0",
    maxSlippagePercent: 1.0,
  };

  it("allows valid transaction intents with correct preflight parameters", () => {
    const preflight: PreflightParams = {
      estimatedGasStroops: 500_000,
      requiresApproval: true,
      approvalGranted: true,
      chainCompatibility: true,
      currentBalance: "1000.0",
      requiredBalance: "50.0",
    };

    const result = engine.evaluate(validIntent, preflight);
    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
    expect(result.evidence.passed).toBe(true);
    expect(result.evidence.intentHash).toBeDefined();
    expect(result.evidence.evaluatorVersion).toBe("1.0.0");
  });

  it("deterministically rejects excessive slippage execution", () => {
    const riskyIntent: TransactionIntent = {
      ...validIntent,
      maxSlippagePercent: 25.0, // exceeds 5.0 threshold
    };

    const preflight: PreflightParams = {
      requiresApproval: true,
      approvalGranted: true,
      chainCompatibility: true,
    };

    const result = engine.evaluate(riskyIntent, preflight);
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === "EXCESSIVE_SLIPPAGE")).toBe(true);
    expect(result.evidence.violations).toHaveLength(1);
    expect(result.evidence.diagnostics).toBeDefined();
  });

  it("blocks approval floods / missing explicit approval", () => {
    const preflight: PreflightParams = {
      requiresApproval: true,
      approvalGranted: false, // missing approval
      chainCompatibility: true,
    };

    const result = engine.evaluate(validIntent, preflight);
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === "MISSING_APPROVAL")).toBe(true);
  });

  it("rejects invalid parameter propagation (negative amount or slippage)", () => {
    const invalidIntent: TransactionIntent = {
      actionType: "transfer",
      sender: "GAB...",
      amount: "-50.0",
      maxSlippagePercent: -1.0,
    };

    const result = engine.evaluate(invalidIntent, { chainCompatibility: true });
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === "INVALID_AMOUNT")).toBe(true);
    expect(result.violations.some((v) => v.code === "INVALID_SLIPPAGE_PARAMETER")).toBe(true);
  });

  it("rejects unsupported chain-state transitions", () => {
    const preflight: PreflightParams = {
      chainCompatibility: false,
      requiresApproval: true,
      approvalGranted: true,
    };

    const result = engine.evaluate(validIntent, preflight);
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === "CHAIN_COMPATIBILITY_FAILURE")).toBe(true);
  });

  it("enforces safety gate across ExecutionEngine path", async () => {
    const result = await executionEngine.execute({
      intent: validIntent,
      preflight: {
        chainCompatibility: false,
      },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("safety engine");
    expect(result.evaluation.allowed).toBe(false);
  });

  it("enforces safety gate across TransactionSubmitter path", async () => {
    const submitter = new TransactionSubmitter();
    const result = await submitter.submitSafely({
      envelopeXdr: "AAAA...",
      intent: {
        ...validIntent,
        maxSlippagePercent: 50.0,
      },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("safety engine");
    expect(result.evaluation.evidence.violations.length).toBeGreaterThan(0);
  });
});
