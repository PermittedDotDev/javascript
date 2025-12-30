# Permitted SDK for TypeScript/JavaScript

Official TypeScript/JavaScript SDK for the [Permitted](https://permitted.dev) licensing platform.

## Installation

```bash
npm install permitted
# or
pnpm add permitted
# or
yarn add permitted
```

## Quick Start

```typescript
import { PermittedClient } from "permitted";

// Create client with your product's API key (from product settings)
const client = new PermittedClient({
  apiKey: "pk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
});

// Validate license with your device identifier
const result = await client.validate("XXXX-XXXX-XXXX-XXXX", identifier);

if (result.license.status === "active") {
  console.log(`Welcome! License valid until: ${result.license.expiresAt}`);

  // Get remote config
  const config = await client.getConfig();
  const maxProjects = config.getInt("max_projects", 5);

  // List available files
  const files = await client.getFiles();
  for (const file of files.files) {
    console.log(`Available: ${file.name} (${file.size} bytes)`);
  }
}
```

## Features

- **Session Management**: Automatic token refresh before expiration
- **Remote Configuration**: Fetch tier-specific config with typed getters
- **Secure File Downloads**: Time-limited signed URLs for protected files
- **Full TypeScript Support**: Complete type definitions
- **Browser & Node.js**: Works in both environments

## Device Identifiers

Unlike native SDKs (C#, Go, Rust), JavaScript cannot access hardware serial numbers due to browser security restrictions. You must provide your own device identifier:

**Server-side applications:**
```typescript
import { createHash } from "crypto";
import { hostname, platform, arch } from "os";

function getDeviceId(): string {
  // Combine server-specific identifiers
  const data = `${hostname()}-${platform()}-${arch()}`;
  return createHash("sha256").update(data).digest("hex");
}
```

**Browser applications:**
```typescript
// Option 1: Server-generated device ID stored in localStorage
const identifier = localStorage.getItem("device_id") ?? await fetchDeviceIdFromServer();

// Option 2: Use a fingerprinting library (less reliable)
import FingerprintJS from "@fingerprintjs/fingerprintjs";
const fp = await FingerprintJS.load();
const result = await fp.get();
const identifier = result.visitorId;
```

**Electron applications:**
```typescript
// In main process - can access real hardware
import { machineIdSync } from "node-machine-id";
const identifier = machineIdSync();
```

**Account-based binding:**
```typescript
// For SaaS apps, use the user's account ID
const identifier = user.id; // e.g., "user_abc123"
```

See the [Device Binding documentation](https://permitted.dev/docs/concepts/device-binding) for more details.

## API Reference

### Validation

```typescript
// Validate license
const result = await client.validate("XXXX-XXXX-XXXX-XXXX", identifier);

// Access validation result
console.log(result.token);               // Session token
console.log(result.expiresAt);           // Token expiration (ISO string)
console.log(result.license.status);      // "active" | "expired" | "suspended" | "revoked"
console.log(result.license.tier?.name);  // Tier name if assigned
```

### Session Management

```typescript
// Check if authenticated
if (client.isAuthenticated) {
  console.log(`Token expires: ${client.tokenExpiresAt}`);
}

// Ensure session is valid (refreshes if needed)
await client.ensureValidSession();

// Manual refresh
const session = await client.refresh();

// Ping to verify session
const ping = await client.ping();
console.log(`Session valid: ${ping.valid}`);
```

### License Info

```typescript
// Get detailed license information
const license = await client.getLicense();

console.log(license.key);
console.log(license.status);
console.log(license.email);
console.log(license.createdAt);
console.log(license.expiresAt);
console.log(license.tier?.name);
```

### Remote Configuration

```typescript
const config = await client.getConfig();

// Typed getters with defaults
const maxProjects = config.getInt("max_projects", 5);
const apiEnabled = config.getBool("api_enabled", false);
const threshold = config.getFloat("threshold", 0.5);
const message = config.getString("welcome_message", "Hello!");

// Raw access
const value = config.variables["custom_key"];
```

### File Downloads

```typescript
// List available files
const files = await client.getFiles();

for (const file of files.files) {
  console.log(`${file.name}: ${file.size} bytes`);
}

// Get signed download URL
const download = await client.getDownloadUrl("file_xxx");
console.log(`Download: ${download.url}`);
console.log(`Expires: ${download.expiresAt}`);

// Download directly with progress
const blob = await client.downloadFile("file_xxx", (downloaded, total) => {
  const percent = total ? Math.round((downloaded / total) * 100) : 0;
  console.log(`Downloading: ${percent}%`);
});

// Save to file (Node.js)
import { writeFile } from "fs/promises";
const buffer = Buffer.from(await blob.arrayBuffer());
await writeFile("/path/to/file", buffer);
```

### API Status

```typescript
// Check API status
const status = await client.getStatus();
console.log(`API Status: ${status.status}`);

// Check status for specific product
const productStatus = await client.getStatus("prod_xxx");
```

## Error Handling

The SDK throws specific errors for different conditions:

```typescript
import {
  PermittedClient,
  InvalidLicenseError,
  LicenseExpiredError,
  LicenseSuspendedError,
  LicenseRevokedError,
  IdentifierMismatchError,
  TokenError,
  RateLimitedError,
  PermittedError,
} from "permitted";

try {
  const result = await client.validate(licenseKey, identifier);
} catch (error) {
  if (error instanceof InvalidLicenseError) {
    console.log("License key not found");
  } else if (error instanceof LicenseExpiredError) {
    console.log("License has expired");
  } else if (error instanceof LicenseSuspendedError) {
    console.log("License is suspended");
  } else if (error instanceof LicenseRevokedError) {
    console.log("License has been revoked");
  } else if (error instanceof IdentifierMismatchError) {
    console.log("Device mismatch - license bound to different device");
  } else if (error instanceof TokenError) {
    console.log(`Session error: ${error.code}`);
  } else if (error instanceof RateLimitedError) {
    console.log(`Rate limited. Retry after: ${error.retryAfterSeconds}s`);
  } else if (error instanceof PermittedError) {
    console.log(`API error [${error.code}]: ${error.message}`);
  }
}
```

### Error Types

| Error | Description |
|-------|-------------|
| `PermittedError` | Base error for all API errors |
| `InvalidLicenseError` | License key not found |
| `LicenseExpiredError` | License validity period ended |
| `LicenseSuspendedError` | License temporarily suspended |
| `LicenseRevokedError` | License permanently revoked |
| `IdentifierMismatchError` | Device doesn't match bound identifier |
| `TokenError` | Session token invalid/expired |
| `RateLimitedError` | Too many requests |
| `ApiDisabledError` | API disabled for product |
| `FileNotFoundError` | Requested file not found |
| `FileAccessDeniedError` | Tier doesn't have file access |
| `DownloadRateLimitedError` | Download rate limit exceeded |

## Configuration

```typescript
// Full configuration options
const client = new PermittedClient({
  // Required: Your product's API key (from product settings > Developer)
  apiKey: "pk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",

  // Optional: Custom API base URL (for self-hosted instances)
  baseUrl: "https://your-instance.permitted.dev/api/v1",
});
```

## Requirements

- Node.js 18+ or modern browser with fetch support
- TypeScript 5.0+ (for type definitions)

## Documentation

See the [Permitted Documentation](https://permitted.dev/docs) for complete API reference and guides.

## License

MIT
