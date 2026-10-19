import { renderTransactionPreview, TransactionIntent, DecodedTransactionData } from './transactionPreview';

describe('renderTransactionPreview', () => {
  it('should generate a safe preview for matching intent and low-risk data', () => {
    const intent: TransactionIntent = {
      action: 'transfer',
      targetAddress: '0x123',
      asset: 'USDC',
      amount: '100',
      network: 'ethereum',
    };

    const decoded: DecodedTransactionData = {
      operation: 'ERC20 Transfer',
      to: '0x123',
      value: '100',
      assetSymbol: 'USDC',
      network: 'ethereum',
      isHighRisk: false,
    };

    const result = renderTransactionPreview(intent, decoded);

    expect(result.intentMatch).toBe(true);
    expect(result.riskWarnings.length).toBe(0);
    expect(result.requiresConfirmation).toBe(false);
    expect(result.summary).toContain('ERC20 Transfer');
  });

  it('should flag warnings and require confirmation for high risk or mismatched actions', () => {
    const intent: TransactionIntent = {
      action: 'transfer',
      targetAddress: '0x123',
      asset: 'USDC',
      amount: '100',
      network: 'ethereum',
    };

    const decoded: DecodedTransactionData = {
      operation: 'Approve Unlimited Allowance',
      to: '0x999',
      value: '1000000',
      assetSymbol: 'USDC',
      network: 'ethereum',
      isHighRisk: true,
      riskReasons: ['Unlimited token approval to untrusted contract'],
    };

    const result = renderTransactionPreview(intent, decoded);

    expect(result.intentMatch).toBe(false);
    expect(result.riskWarnings.length).toBeGreaterThan(0);
    expect(result.requiresConfirmation).toBe(true);
    expect(result.auditTrail).toBeDefined();
  });
});
