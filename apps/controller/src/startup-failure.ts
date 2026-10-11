import { KubernetesApiUnavailableError } from "./drivers/kubernetes/client.ts";

/**
 * Log fields for a startup failure caused by an unreachable dependency, naming
 * the dependency class in `code` and its address in `host` and `port`.
 */
export function startupDependencyFailure(
  error: unknown,
): { readonly code: string; readonly host: string; readonly port: number } | undefined {
  if (error instanceof KubernetesApiUnavailableError) {
    return { code: "KUBERNETES_API_UNAVAILABLE", host: error.host, port: error.port };
  }
  return undefined;
}

const RESERVED_NETWORK_POLICY_NAME =
  "OpenShell network policy name workspace-node-enrollment is reserved.";
const NETWORK_POLICY_NAME_PREFIX = "OpenShell network policy name ";
const DUPLICATE_NETWORK_POLICY_SUFFIX = " must be unique.";

/**
 * Startup log for a rejected OpenShell policy name. The code and the
 * rename-or-merge action are fixed; the operator's policy name stays out of the log.
 */
export function startupPolicyNameFailure(error: unknown):
  | {
      readonly code: "OPENSHELL_NETWORK_POLICY_NAME_REJECTED";
      readonly reason: "rename-or-merge";
    }
  | undefined {
  const message = error instanceof Error ? error.message : "";
  const duplicate =
    message.startsWith(NETWORK_POLICY_NAME_PREFIX) &&
    message.endsWith(DUPLICATE_NETWORK_POLICY_SUFFIX) &&
    message.length <= 1024;
  if (message !== RESERVED_NETWORK_POLICY_NAME && !duplicate) {
    return undefined;
  }
  return {
    code: "OPENSHELL_NETWORK_POLICY_NAME_REJECTED",
    reason: "rename-or-merge",
  };
}
