export class LicenseError extends Error {
  code: string;
}
export type Config = {
  url: string;
  product: string;
  issuer: string;
  keys: Record<string, string>;
  cache: string;
  allowHttp?: boolean;
  timeout?: number;
};
export type LicenseStatus = {
  status: string;
  error?: string;
  license_id?: string;
  expires_at?: number | null;
  credential_expires_at?: number;
  perpetual?: boolean;
  features?: string[];
  quotas?: Record<string, number>;
};
export function verifyToken(
  token: string,
  options: {
    keys: Record<string, string>;
    issuer: string;
    product: string;
    instance: string;
    now?: number;
  },
): Record<string, unknown>;
export class LicenseClient {
  constructor(config: Config);
  initialize(instance?: string): this;
  activate(
    code: string,
    customer: string,
    options?: { idempotencyKey?: string },
  ): Promise<LicenseStatus>;
  activateExisting(
    licenseId: string,
    licenseSecret: string,
    options: { idempotencyKey: string },
  ): Promise<LicenseStatus>;
  refresh(): Promise<LicenseStatus>;
  renew(
    code: string,
    options: { idempotencyKey: string },
  ): Promise<Record<string, unknown>>;
  getLicenseStatus(): LicenseStatus;
  requireFeature(feature: string): Promise<boolean>;
  checkQuota(
    name: string,
    current: number,
    additional?: number,
  ): Promise<boolean>;
  deactivate(): Promise<Record<string, unknown>>;
  installOffline(path: string): LicenseStatus;
  startBackgroundRefresh(): void;
  close(): void;
}
