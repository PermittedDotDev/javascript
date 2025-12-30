/**
 * Permitted SDK for TypeScript/JavaScript
 *
 * @example
 * ```typescript
 * import { PermittedClient } from "permitted";
 *
 * const client = new PermittedClient({
 *   apiKey: "pk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
 * });
 *
 * // Validate license with your device identifier
 * const result = await client.validate("XXXX-XXXX-XXXX-XXXX", deviceId);
 *
 * if (result.license.status === "active") {
 *   const config = await client.getConfig();
 *   console.log("Max projects:", config.getInt("max_projects", 5));
 * }
 * ```
 *
 * @packageDocumentation
 */

export const VERSION = "0.1.0";

// ============================================================================
// Types
// ============================================================================

export interface PermittedClientOptions {
  /** Product API key (required). Found in your product's Developer settings. */
  apiKey: string;
  /** Base URL for the API. Defaults to https://permitted.dev/api/v1 */
  baseUrl?: string;
}

export interface StatusResult {
  status: "ok" | "maintenance" | "disabled";
  message?: string;
}

export interface LicenseTier {
  id: string;
  name: string;
  description?: string;
}

export interface License {
  id: string;
  key: string;
  status: "active" | "expired" | "suspended" | "revoked";
  email?: string;
  identifier?: string;
  tier?: LicenseTier;
  metadata?: Record<string, unknown>;
  createdAt: string;
  expiresAt?: string;
  activatedAt?: string;
}

export interface ValidationResult {
  token: string;
  expiresAt: string;
  license: License;
}

export interface SessionRefreshResult {
  token: string;
  expiresAt: string;
}

export interface PingResult {
  valid: boolean;
  expiresAt?: string;
}

export interface ConfigVariable {
  key: string;
  value: string;
  type: "string" | "number" | "boolean" | "json";
}

export interface ConfigResult {
  variables: Record<string, string>;

  /** Get a string value with optional default */
  getString(key: string, defaultValue?: string): string | undefined;

  /** Get an integer value with optional default */
  getInt(key: string, defaultValue?: number): number | undefined;

  /** Get a float value with optional default */
  getFloat(key: string, defaultValue?: number): number | undefined;

  /** Get a boolean value with optional default */
  getBool(key: string, defaultValue?: boolean): boolean | undefined;
}

export interface FileInfo {
  id: string;
  name: string;
  size: number;
  contentType: string;
  checksum: string;
  createdAt: string;
}

export interface FilesResult {
  files: FileInfo[];
}

export interface DownloadResult {
  url: string;
  expiresAt: string;
}

export interface ErrorInfo {
  code: string;
  message: string;
}

// ============================================================================
// Errors
// ============================================================================

/**
 * Base exception for all Permitted API errors.
 */
export class PermittedError extends Error {
  public readonly code: string;
  public readonly statusCode?: number;

  constructor(code: string, message: string, statusCode?: number) {
    super(message);
    this.name = "PermittedError";
    this.code = code;
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, PermittedError.prototype);
  }
}

/**
 * License key was not found.
 */
export class InvalidLicenseError extends PermittedError {
  constructor(message: string = "License key not found") {
    super("INVALID_LICENSE", message, 404);
    this.name = "InvalidLicenseError";
    Object.setPrototypeOf(this, InvalidLicenseError.prototype);
  }
}

/**
 * License has expired.
 */
export class LicenseExpiredError extends PermittedError {
  constructor(message: string = "License has expired") {
    super("LICENSE_EXPIRED", message, 403);
    this.name = "LicenseExpiredError";
    Object.setPrototypeOf(this, LicenseExpiredError.prototype);
  }
}

/**
 * License is suspended.
 */
export class LicenseSuspendedError extends PermittedError {
  constructor(message: string = "License is suspended") {
    super("LICENSE_SUSPENDED", message, 403);
    this.name = "LicenseSuspendedError";
    Object.setPrototypeOf(this, LicenseSuspendedError.prototype);
  }
}

/**
 * License has been revoked.
 */
export class LicenseRevokedError extends PermittedError {
  constructor(message: string = "License has been revoked") {
    super("LICENSE_REVOKED", message, 403);
    this.name = "LicenseRevokedError";
    Object.setPrototypeOf(this, LicenseRevokedError.prototype);
  }
}

/**
 * Identifier doesn't match the bound device.
 */
export class IdentifierMismatchError extends PermittedError {
  constructor(message: string = "Identifier mismatch") {
    super("IDENTIFIER_MISMATCH", message, 403);
    this.name = "IdentifierMismatchError";
    Object.setPrototypeOf(this, IdentifierMismatchError.prototype);
  }
}

/**
 * Session token is invalid or expired.
 */
export class TokenError extends PermittedError {
  constructor(code: string, message: string) {
    super(code, message, 401);
    this.name = "TokenError";
    Object.setPrototypeOf(this, TokenError.prototype);
  }
}

/**
 * Too many requests - rate limited.
 */
export class RateLimitedError extends PermittedError {
  public readonly retryAfterSeconds?: number;

  constructor(message: string = "Rate limit exceeded", retryAfter?: number) {
    super("RATE_LIMITED", message, 429);
    this.name = "RateLimitedError";
    this.retryAfterSeconds = retryAfter;
    Object.setPrototypeOf(this, RateLimitedError.prototype);
  }
}

/**
 * API is disabled for this product.
 */
export class ApiDisabledError extends PermittedError {
  constructor(message: string = "API is disabled") {
    super("API_DISABLED", message, 503);
    this.name = "ApiDisabledError";
    Object.setPrototypeOf(this, ApiDisabledError.prototype);
  }
}

/**
 * File not found.
 */
export class FileNotFoundError extends PermittedError {
  constructor(message: string = "File not found") {
    super("FILE_NOT_FOUND", message, 404);
    this.name = "FileNotFoundError";
    Object.setPrototypeOf(this, FileNotFoundError.prototype);
  }
}

/**
 * File access denied for this tier.
 */
export class FileAccessDeniedError extends PermittedError {
  constructor(message: string = "File access denied") {
    super("FILE_ACCESS_DENIED", message, 403);
    this.name = "FileAccessDeniedError";
    Object.setPrototypeOf(this, FileAccessDeniedError.prototype);
  }
}

/**
 * Download rate limit exceeded.
 */
export class DownloadRateLimitedError extends PermittedError {
  constructor(message: string = "Download rate limit exceeded") {
    super("DOWNLOAD_RATE_LIMITED", message, 429);
    this.name = "DownloadRateLimitedError";
    Object.setPrototypeOf(this, DownloadRateLimitedError.prototype);
  }
}

// ============================================================================
// Client
// ============================================================================

const DEFAULT_BASE_URL = "https://permitted.dev/api/v1";
const REFRESH_MARGIN_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Main client for interacting with the Permitted API.
 * Handles license validation, session management, remote config, and file downloads.
 *
 * @example
 * ```typescript
 * const client = new PermittedClient({
 *   apiKey: "pk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
 * });
 *
 * // Validate license
 * const result = await client.validate("XXXX-XXXX-XXXX-XXXX", deviceId);
 *
 * if (result.license.status === "active") {
 *   const config = await client.getConfig();
 *   console.log("Max projects:", config.getInt("max_projects", 5));
 * }
 * ```
 */
export class PermittedClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private token?: string;
  private expiresAt?: Date;
  private licenseKey?: string;
  private identifier?: string;

  constructor(options: PermittedClientOptions) {
    if (!options?.apiKey) {
      throw new Error("API key is required");
    }
    this.apiKey = options.apiKey;

    let baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    if (!baseUrl.endsWith("/")) {
      baseUrl += "/";
    }
    this.baseUrl = baseUrl;
  }

  // --------------------------------------------------------------------------
  // Public Properties
  // --------------------------------------------------------------------------

  /**
   * Whether the client has a valid session.
   */
  get isAuthenticated(): boolean {
    return !!this.token && !!this.expiresAt && this.expiresAt > new Date();
  }

  /**
   * The current token, if authenticated.
   */
  get currentToken(): string | undefined {
    return this.token;
  }

  /**
   * When the current token expires.
   */
  get tokenExpiresAt(): Date | undefined {
    return this.expiresAt;
  }

  // --------------------------------------------------------------------------
  // Status
  // --------------------------------------------------------------------------

  /**
   * Checks API availability.
   */
  async getStatus(productId?: string): Promise<StatusResult> {
    let url = "status";
    if (productId) {
      url += `?product_id=${encodeURIComponent(productId)}`;
    }
    return this.request<StatusResult>("GET", url);
  }

  // --------------------------------------------------------------------------
  // Validation
  // --------------------------------------------------------------------------

  /**
   * Validates a license key and establishes a session.
   *
   * @param licenseKey - The license key to validate
   * @param identifier - Device identifier for binding (hardware fingerprint, account ID, or installation ID)
   * @throws InvalidLicenseError - License key not found
   * @throws LicenseExpiredError - License has expired
   * @throws LicenseSuspendedError - License is suspended
   * @throws IdentifierMismatchError - Device doesn't match
   */
  async validate(licenseKey: string, identifier: string): Promise<ValidationResult> {
    const result = await this.request<{
      token: string;
      expires_at: string;
      license: {
        id: string;
        key: string;
        status: string;
        email?: string;
        identifier?: string;
        tier?: { id: string; name: string; description?: string };
        metadata?: Record<string, unknown>;
        created_at: string;
        expires_at?: string;
        activated_at?: string;
      };
    }>("POST", "license/validate", {
      license_key: licenseKey,
      identifier,
    });

    // Store session
    this.token = result.token;
    this.expiresAt = new Date(result.expires_at);
    this.licenseKey = licenseKey;
    this.identifier = identifier;

    return {
      token: result.token,
      expiresAt: result.expires_at,
      license: this.transformLicense(result.license),
    };
  }

  // --------------------------------------------------------------------------
  // Session
  // --------------------------------------------------------------------------

  /**
   * Refreshes the current session token.
   *
   * @throws TokenError - Token is invalid or expired
   */
  async refresh(): Promise<SessionRefreshResult> {
    if (!this.token) {
      throw new Error("No active session. Call validate() first.");
    }

    const result = await this.request<{
      token: string;
      expires_at: string;
    }>("POST", "session/refresh", { token: this.token });

    this.token = result.token;
    this.expiresAt = new Date(result.expires_at);

    return {
      token: result.token,
      expiresAt: result.expires_at,
    };
  }

  /**
   * Checks if the current session is valid.
   */
  async ping(): Promise<PingResult> {
    await this.ensureAuthenticated();

    const result = await this.request<{
      valid: boolean;
      expires_at?: string;
    }>("GET", "ping");

    return {
      valid: result.valid,
      expiresAt: result.expires_at,
    };
  }

  /**
   * Ensures the session is valid, refreshing if necessary.
   */
  async ensureValidSession(): Promise<void> {
    if (!this.token) {
      throw new Error("No active session. Call validate() first.");
    }

    if (this.shouldRefresh()) {
      try {
        await this.refresh();
      } catch (error) {
        if (error instanceof TokenError && this.licenseKey && this.identifier) {
          await this.validate(this.licenseKey, this.identifier);
        } else {
          throw error;
        }
      }
    }
  }

  // --------------------------------------------------------------------------
  // License
  // --------------------------------------------------------------------------

  /**
   * Gets detailed information about the current license.
   */
  async getLicense(): Promise<License> {
    await this.ensureAuthenticated();

    const result = await this.request<{
      id: string;
      key: string;
      status: string;
      email?: string;
      identifier?: string;
      tier?: { id: string; name: string; description?: string };
      metadata?: Record<string, unknown>;
      created_at: string;
      expires_at?: string;
      activated_at?: string;
    }>("GET", "license");

    return this.transformLicense(result);
  }

  // --------------------------------------------------------------------------
  // Config
  // --------------------------------------------------------------------------

  /**
   * Gets remote configuration values.
   */
  async getConfig(): Promise<ConfigResult> {
    await this.ensureAuthenticated();

    const result = await this.request<{
      variables: Record<string, string>;
    }>("GET", "config");

    return this.createConfigResult(result.variables);
  }

  // --------------------------------------------------------------------------
  // Files
  // --------------------------------------------------------------------------

  /**
   * Lists available files for download.
   */
  async getFiles(): Promise<FilesResult> {
    await this.ensureAuthenticated();

    const result = await this.request<{
      files: Array<{
        id: string;
        name: string;
        size: number;
        content_type: string;
        checksum: string;
        created_at: string;
      }>;
    }>("GET", "files");

    return {
      files: result.files.map((f) => ({
        id: f.id,
        name: f.name,
        size: f.size,
        contentType: f.content_type,
        checksum: f.checksum,
        createdAt: f.created_at,
      })),
    };
  }

  /**
   * Gets a signed download URL for a file.
   *
   * @param fileId - The file ID to download
   * @throws FileNotFoundError - File not found
   * @throws FileAccessDeniedError - Access denied
   * @throws DownloadRateLimitedError - Rate limit exceeded
   */
  async getDownloadUrl(fileId: string): Promise<DownloadResult> {
    await this.ensureAuthenticated();

    const result = await this.request<{
      url: string;
      expires_at: string;
    }>("GET", `files/${encodeURIComponent(fileId)}/download`);

    return {
      url: result.url,
      expiresAt: result.expires_at,
    };
  }

  /**
   * Downloads a file as a Blob (browser) or Buffer (Node.js).
   *
   * @param fileId - The file ID to download
   * @param onProgress - Optional progress callback
   */
  async downloadFile(
    fileId: string,
    onProgress?: (downloaded: number, total: number | null) => void
  ): Promise<Blob | ArrayBuffer> {
    const { url } = await this.getDownloadUrl(fileId);

    const response = await fetch(url);
    if (!response.ok) {
      throw new PermittedError(
        "DOWNLOAD_FAILED",
        `Download failed with status ${response.status}`,
        response.status
      );
    }

    const contentLength = response.headers.get("content-length");
    const total = contentLength ? parseInt(contentLength, 10) : null;

    if (!response.body) {
      return response.blob();
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let downloaded = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      chunks.push(value);
      downloaded += value.length;
      onProgress?.(downloaded, total);
    }

    const blob = new Blob(chunks);
    return blob;
  }

  // --------------------------------------------------------------------------
  // Private Methods
  // --------------------------------------------------------------------------

  private async ensureAuthenticated(): Promise<void> {
    if (!this.token) {
      throw new Error("No active session. Call validate() first.");
    }

    if (this.shouldRefresh()) {
      await this.refresh();
    }
  }

  private shouldRefresh(): boolean {
    if (!this.expiresAt) return true;
    return Date.now() >= this.expiresAt.getTime() - REFRESH_MARGIN_MS;
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = this.baseUrl + path;
    const headers: Record<string, string> = {
      "User-Agent": `permitted-js/${VERSION}`,
      Accept: "application/json",
      "X-API-Key": this.apiKey,
    };

    if (body) {
      headers["Content-Type"] = "application/json";
    }

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (response.ok) {
      return response.json() as Promise<T>;
    }

    // Handle errors
    let error: ErrorInfo | undefined;
    try {
      const json = (await response.json()) as { error?: ErrorInfo };
      error = json.error;
    } catch {
      // Could not parse error
    }

    const code = error?.code ?? "UNKNOWN_ERROR";
    const message =
      error?.message ?? `Request failed with status ${response.status}`;

    throw this.createError(code, message, response);
  }

  private createError(
    code: string,
    message: string,
    response: Response
  ): PermittedError {
    switch (code) {
      case "INVALID_LICENSE":
        return new InvalidLicenseError(message);
      case "LICENSE_EXPIRED":
        return new LicenseExpiredError(message);
      case "LICENSE_SUSPENDED":
        return new LicenseSuspendedError(message);
      case "LICENSE_REVOKED":
        return new LicenseRevokedError(message);
      case "IDENTIFIER_MISMATCH":
        return new IdentifierMismatchError(message);
      case "TOKEN_MISSING":
      case "TOKEN_INVALID":
      case "TOKEN_EXPIRED":
      case "TOKEN_REVOKED":
        return new TokenError(code, message);
      case "API_DISABLED":
        return new ApiDisabledError(message);
      case "RATE_LIMITED":
        const retryAfter = response.headers.get("Retry-After");
        return new RateLimitedError(
          message,
          retryAfter ? parseInt(retryAfter, 10) : undefined
        );
      case "FILE_NOT_FOUND":
        return new FileNotFoundError(message);
      case "FILE_ACCESS_DENIED":
        return new FileAccessDeniedError(message);
      case "DOWNLOAD_RATE_LIMITED":
        return new DownloadRateLimitedError(message);
      default:
        return new PermittedError(code, message, response.status);
    }
  }

  private transformLicense(raw: {
    id: string;
    key: string;
    status: string;
    email?: string;
    identifier?: string;
    tier?: { id: string; name: string; description?: string };
    metadata?: Record<string, unknown>;
    created_at: string;
    expires_at?: string;
    activated_at?: string;
  }): License {
    return {
      id: raw.id,
      key: raw.key,
      status: raw.status as License["status"],
      email: raw.email,
      identifier: raw.identifier,
      tier: raw.tier,
      metadata: raw.metadata,
      createdAt: raw.created_at,
      expiresAt: raw.expires_at,
      activatedAt: raw.activated_at,
    };
  }

  private createConfigResult(variables: Record<string, string>): ConfigResult {
    return {
      variables,

      getString(key: string, defaultValue?: string): string | undefined {
        return variables[key] ?? defaultValue;
      },

      getInt(key: string, defaultValue?: number): number | undefined {
        const value = variables[key];
        if (value === undefined) return defaultValue;
        const parsed = parseInt(value, 10);
        return isNaN(parsed) ? defaultValue : parsed;
      },

      getFloat(key: string, defaultValue?: number): number | undefined {
        const value = variables[key];
        if (value === undefined) return defaultValue;
        const parsed = parseFloat(value);
        return isNaN(parsed) ? defaultValue : parsed;
      },

      getBool(key: string, defaultValue?: boolean): boolean | undefined {
        const value = variables[key];
        if (value === undefined) return defaultValue;
        return value === "true" || value === "1";
      },
    };
  }
}

// Re-export everything
export default PermittedClient;
