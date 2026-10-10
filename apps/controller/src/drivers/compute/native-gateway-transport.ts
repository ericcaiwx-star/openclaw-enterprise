import type { OpenClawConfigurationDocument } from "@openclaw-enterprise/contracts";
import { ComputeGatewaySettingError } from "@openclaw-enterprise/occ";
import { asRecord } from "@openclaw-enterprise/utils";

// These Compute Drivers use the native HTTP listener for readiness and private
// traffic. TLS on an outer proxy is independent of the native listener setting.
export function validatePlaintextNativeGateway(
  configuration: Readonly<OpenClawConfigurationDocument>,
  createError: (setting: string, requirement: string) => Error = (setting, requirement) =>
    new ComputeGatewaySettingError(setting, requirement),
): void {
  const tls = asRecord(asRecord(configuration.gateway)?.tls);
  if (tls?.enabled === true) {
    throw createError(
      "gateway.tls.enabled",
      "must be omitted or false: Compute uses the native HTTP listener for readiness and private traffic",
    );
  }
}
