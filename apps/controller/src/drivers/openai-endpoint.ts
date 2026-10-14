import { isIP } from "node:net";

const strictDecimalIpv4 = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;

// Node rewrites shorthand, integer, hex, and leading-zero IPv4 hosts before
// `origin` is read, so those spellings must not be stored as the other address.
function rewrittenIpv4Host(raw: string, endpoint: URL): boolean {
  if (isIP(endpoint.hostname) !== 4) {
    return false;
  }
  const written = /^[a-z][a-z\d+.-]*:\/\/(?:[^/?#@]*@)?([^/?#:]+)/i.exec(raw)?.[1];
  return written !== endpoint.hostname || !strictDecimalIpv4.test(endpoint.hostname);
}

/** Shared endpoint validation for the Compute and Credential Gateway Drivers. */
export function normalizeOpenAiBaseUrl(value: string): string | undefined {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    return undefined;
  }
  const path = endpoint.pathname.replace(/\/$/u, "");
  if (
    rewrittenIpv4Host(value, endpoint) ||
    endpoint.protocol !== "https:" ||
    endpoint.hostname.length === 0 ||
    // WHATWG decodes hostname escapes but permits stars that profiles treat as patterns.
    endpoint.hostname.includes("*") ||
    endpoint.port === "0" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    !path.endsWith("/v1") ||
    path.includes("*") ||
    endpoint.search !== "" ||
    endpoint.hash !== ""
  ) {
    return undefined;
  }
  return endpoint.origin + path;
}
