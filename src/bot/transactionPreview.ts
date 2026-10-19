export interface TransactionIntent {
  action: string;
  targetAddress: string;
  asset?: string;
  amount?: string;
  network?: string;
}

export interface DecodedTransactionData {
  operation: string;
  to: string;
  value?: string;
  assetSymbol?: string;
  network: string;
  dataPayload?: string;
  isHighRisk?: boolean;
  riskReasons?: string[];
}

export interface TransactionPreviewResult {
  summary: string;
  network: string;
  asset: string;
  address: string;
  riskWarnings: string[];
  intentMatch: boolean;
  auditTrail: {
    userRequest: string;
    decodedData: DecodedTransactionData;
    timestamp: number;
  };
  requiresConfirmation: boolean;
}

export function renderTransactionPreview(
  intent: TransactionIntent,
  decoded: DecodedTransactionData
): TransactionPreviewResult {
  const warnings: string[] = [];

  if (decoded.isHighRisk) {
    warnings.push('HIGH RISK: This transaction involves uncommon or high-impact actions.');
  }

  if (decoded.to.toLowerCase() !== intent.targetAddress.toLowerCase()) {
    warnings.push('WARNING: Target address differs from the requested intent address.');
  }

  if (intent.asset && decoded.assetSymbol && intent.asset.toLowerCase() !== decoded.assetSymbol.toLowerCase()) {
    warnings.push('WARNING: Asset symbol mismatch between intent and decoded payload.');
  }

  const intentMatch =
    decoded.operation.toLowerCase().includes(intent.action.toLowerCase()) &&
    decoded.to.toLowerCase() === intent.targetAddress.toLowerCase();

  if (!intentMatch) {
    warnings.push('CRITICAL: Transaction actions do not match the original user intent.');
  }

  const requiresConfirmation = warnings.length > 0 || decoded.isHighRisk === true;

  const summary = `Operation: ${decoded.operation} on ${decoded.network}. Asset: ${decoded.assetSymbol || 'N/A'} (Amount: ${decoded.value || 'N/A'}), To: ${decoded.to}`;

  return {
    summary,
    network: decoded.network,
    asset: decoded.assetSymbol || 'N/A',
    address: decoded.to,
    riskWarnings: warnings,
    intentMatch,
    auditTrail: {
      userRequest: JSON.stringify(intent),
      decodedData: decoded,
      timestamp: Date.now(),
    },
    requiresConfirmation,
  };
}
