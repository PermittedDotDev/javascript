# permitted

Official Permitted SDK for TypeScript and JavaScript.

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
import { Permitted } from "permitted";

// Initialize the client
const permitted = new Permitted();

// Validate a license
const license = await permitted.validate({
  licenseKey: "XXXX-XXXX-XXXX-XXXX",
  hwid: getHardwareId(), // Your hardware ID implementation
});

if (license.status === "active") {
  console.log(`License valid until: ${license.expiresAt}`);

  // Get remote config
  const config = await permitted.getConfig();
  console.log("Config:", config.variables);

  // List available files
  const files = await permitted.getFiles();
  console.log("Available files:", files);
}
```

## Features

- License validation with HWID binding
- Automatic session refresh
- Remote configuration
- File downloads with signed URLs
- Full TypeScript support

## Documentation

See the [Permitted Documentation](https://permitted.io/docs) for complete API reference and guides.

## License

MIT
