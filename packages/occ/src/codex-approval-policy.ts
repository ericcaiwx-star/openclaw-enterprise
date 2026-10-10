import type {
  OpenClawConfigurationDocument,
  PluginDesiredState,
} from "@openclaw-enterprise/contracts";
import { asRecord } from "@openclaw-enterprise/utils";

import { ConfigurationHarnessError } from "./errors.ts";

const SETTING = "plugins.entries.codex.config.appServer.approvalPolicy";

function configuredApprovalPolicy(values: Readonly<OpenClawConfigurationDocument>): unknown {
  const codex = asRecord(asRecord(asRecord(values.plugins)?.entries)?.codex);
  return asRecord(asRecord(codex?.config)?.appServer)?.approvalPolicy;
}

/**
 * The pinned OpenClaw Gateway refuses `untrusted` when it loads its configuration, and its
 * `openclaw doctor --fix` hint cannot edit the read-only configuration Compute renders, so
 * Configuration writes and deployment refuse it here instead. The Gateway runs `on-failure`
 * as `on-request` and Compute renders it that way, so it stays accepted.
 */
export function validateCodexApprovalPolicySetting(
  values: Readonly<OpenClawConfigurationDocument>,
): void {
  if (configuredApprovalPolicy(values) === "untrusted") {
    throw new ConfigurationHarnessError(
      `Configuration setting ${SETTING} "untrusted" is retired by the OpenClaw runtime; use "on-request".`,
    );
  }
}

/**
 * Native startup checks an automatic plugin reviewer against the session approval policy in
 * its startup configuration, which Compute copies from the configured policy. When the policy
 * is omitted, the Gateway picks its own session policy (`never` without managed requirements),
 * which the startup check cannot see, so deployment requires the explicit policy instead.
 */
export function validateCodexAutomaticReviewerPolicy(
  values: Readonly<OpenClawConfigurationDocument>,
  plugins: PluginDesiredState | undefined,
): void {
  const automatic = Object.values(plugins ?? {}).some(
    (selection) => selection?.enabled === true && selection.toolDefaults?.reviewer === "auto",
  );
  const policy = configuredApprovalPolicy(values);
  if (automatic && policy !== "on-request" && policy !== "on-failure") {
    throw new ConfigurationHarnessError(
      `An automatic plugin reviewer requires Configuration setting ${SETTING} "on-request"; ${
        policy === undefined ? "set it explicitly" : "change it"
      } or choose the human reviewer.`,
    );
  }
}
