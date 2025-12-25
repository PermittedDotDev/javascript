/**
 * Permitted SDK for TypeScript/JavaScript
 *
 * @example
 * ```typescript
 * import { Permitted } from "permitted";
 *
 * const permitted = new Permitted();
 *
 * const license = await permitted.validate({
 *   licenseKey: "XXXX-XXXX-XXXX-XXXX",
 *   hwid: getHardwareId(),
 * });
 *
 * if (license.status === "active") {
 *   const config = await permitted.getConfig();
 *   console.log("Welcome!", config.variables);
 * }
 * ```
 *
 * @packageDocumentation
 */

// TODO: Implement SDK
// See API_V1_SPECIFICATION.md for endpoint details

export const VERSION = "0.0.1";

export class Permitted {
  // Placeholder - implementation coming soon
}
