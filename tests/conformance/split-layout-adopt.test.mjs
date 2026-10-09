import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AdoptError,
  JOURNAL_ANNOTATION,
  applyAdoption,
  createKubectl,
  finalizeAdoption,
  planAll,
  revertAdoption,
  storageNamespaceName,
} from "../../scripts/split-layout-adopt.mjs";

// The script drives a cluster only through kubectl. This fake answers the kubectl commands it
// issues from an in-memory object store and models the API-server and controller behaviour the
// adoption depends on: UID preconditions on delete, the PVC protection finalizer, the reclaim
// policy of a released volume, pre-bound claim references, Deployment scaling and Namespace
// deletion. It does not prove kubectl's own flag handling; the scratch-cluster proof does.
const RESOURCES = {
  namespaces: { kind: "Namespace", apiVersion: "v1", cluster: true },
  persistentvolumes: { kind: "PersistentVolume", apiVersion: "v1", cluster: true },
  persistentvolumeclaims: { kind: "PersistentVolumeClaim", apiVersion: "v1" },
  secrets: { kind: "Secret", apiVersion: "v1" },
  configmaps: { kind: "ConfigMap", apiVersion: "v1" },
  serviceaccounts: { kind: "ServiceAccount", apiVersion: "v1" },
  services: { kind: "Service", apiVersion: "v1" },
  pods: { kind: "Pod", apiVersion: "v1" },
  events: { kind: "Event", apiVersion: "v1" },
  "deployments.apps": { kind: "Deployment", apiVersion: "apps/v1" },
  "rolebindings.rbac.authorization.k8s.io": {
    kind: "RoleBinding",
    apiVersion: "rbac.authorization.k8s.io/v1",
  },
  "networkpolicies.networking.k8s.io": {
    kind: "NetworkPolicy",
    apiVersion: "networking.k8s.io/v1",
  },
  "httproutes.gateway.networking.k8s.io": {
    kind: "HTTPRoute",
    apiVersion: "gateway.networking.k8s.io/v1",
  },
  "securitypolicies.gateway.envoyproxy.io": {
    kind: "SecurityPolicy",
    apiVersion: "gateway.envoyproxy.io/v1alpha1",
  },
};
const resourceOfKind = (kind) =>
  Object.entries(RESOURCES).find(([, spec]) => spec.kind === kind)[0];

function mergePatch(target, patch) {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
    return patch;
  }
  const result = target !== null && typeof target === "object" ? { ...target } : {};
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) {
      delete result[key];
    } else {
      result[key] = mergePatch(result[key], value);
    }
  }
  return result;
}

function fakeCluster() {
  const store = new Map();
  let serial = 0;
  const calls = [];
  const failures = [];
  const key = (resource, namespace, name) =>
    `${resource}/${RESOURCES[resource].cluster ? "" : namespace}/${name}`;
  const put = (resource, object) => {
    serial += 1;
    object.metadata.uid ??= `uid-${serial}`;
    object.metadata.resourceVersion = String(serial);
    object.metadata.creationTimestamp ??= "2026-09-28T00:00:00Z";
    object.apiVersion = RESOURCES[resource].apiVersion;
    object.kind = RESOURCES[resource].kind;
    store.set(key(resource, object.metadata.namespace, object.metadata.name), object);
    return object;
  };
  const get = (resource, namespace, name) => store.get(key(resource, namespace, name));
  const items = (resource, namespace) =>
    [...store.entries()]
      .filter(
        ([entry, object]) =>
          entry.startsWith(`${resource}/`) &&
          (RESOURCES[resource].cluster || object.metadata.namespace === namespace),
      )
      .map(([, object]) => object);
  const mounted = (namespace, claim) =>
    items("pods", namespace).some((pod) =>
      (pod.spec?.volumes ?? []).some((volume) => volume.persistentVolumeClaim?.claimName === claim),
    );
  // The PersistentVolume controller and the PVC protection finalizer, run after every command.
  const reconcile = () => {
    for (const [entry, claim] of [...store.entries()].filter(([entry]) =>
      entry.startsWith("persistentvolumeclaims/"),
    )) {
      if (
        claim.metadata.deletionTimestamp &&
        !mounted(claim.metadata.namespace, claim.metadata.name)
      ) {
        store.delete(entry);
        const volume = get("persistentvolumes", undefined, claim.spec.volumeName);
        if (volume?.spec.claimRef?.uid === claim.metadata.uid) {
          if (volume.spec.persistentVolumeReclaimPolicy === "Delete") {
            store.delete(key("persistentvolumes", undefined, volume.metadata.name));
          } else {
            volume.status = { phase: "Released" };
          }
        }
        continue;
      }
      const volume = get("persistentvolumes", undefined, claim.spec.volumeName);
      const reference = volume?.spec.claimRef;
      if (
        claim.status?.phase !== "Bound" &&
        reference?.namespace === claim.metadata.namespace &&
        reference.name === claim.metadata.name &&
        (reference.uid === undefined || reference.uid === claim.metadata.uid) &&
        (volume.spec.storageClassName ?? "") === (claim.spec.storageClassName ?? "")
      ) {
        reference.uid = claim.metadata.uid;
        volume.status = { phase: "Bound" };
        claim.status = { phase: "Bound" };
      }
    }
  };
  const remove = (resource, object) => {
    if (resource === "persistentvolumeclaims") {
      object.metadata.deletionTimestamp = "2026-10-09T00:00:00Z";
      return;
    }
    store.delete(key(resource, object.metadata.namespace, object.metadata.name));
    if (resource === "namespaces") {
      for (const [entry, child] of [...store.entries()]) {
        if (child.metadata.namespace === object.metadata.name) {
          const childResource = entry.split("/")[0];
          if (childResource === "persistentvolumeclaims") {
            remove(childResource, child);
          } else {
            store.delete(entry);
          }
        }
      }
    }
  };
  const flag = (args, name) => {
    const index = args.indexOf(name);
    return index === -1 ? undefined : args[index + 1];
  };
  const run = (args, input) => {
    calls.push(args.join(" "));
    const failure = failures.findIndex((match) => match(args, input));
    if (failure !== -1) {
      failures.splice(failure, 1);
      return { status: 1, stdout: "", stderr: "injected failure" };
    }
    const ok = (value) => ({
      status: 0,
      stdout: value === undefined ? "" : JSON.stringify(value),
      stderr: "",
    });
    const namespace = flag(args, "-n");
    try {
      switch (args[0]) {
        case "api-resources":
          return {
            status: 0,
            stdout: Object.keys(RESOURCES)
              .filter((resource) => !RESOURCES[resource].cluster)
              .join("\n"),
            stderr: "",
          };
        case "get": {
          const resource = args[1];
          const named = args[2] !== undefined && !args[2].startsWith("-");
          if (named) {
            const object = get(resource, namespace, args[2]);
            return ok(object === undefined ? undefined : structuredClone(object));
          }
          const selector = flag(args, "-l");
          const [label, value] = selector === undefined ? [] : selector.split("=");
          return ok({
            items: items(resource, namespace)
              .filter(
                (object) =>
                  label === undefined ||
                  (value === undefined
                    ? object.metadata.labels?.[label] !== undefined
                    : object.metadata.labels?.[label] === value),
              )
              .map((object) => structuredClone(object)),
          });
        }
        case "create": {
          const body = JSON.parse(input);
          const resource = resourceOfKind(body.kind);
          if (get(resource, body.metadata.namespace, body.metadata.name) !== undefined) {
            return { status: 1, stdout: "", stderr: `${body.metadata.name} already exists` };
          }
          assert.equal(body.metadata.uid, undefined, "create must not carry a UID");
          const created = put(resource, structuredClone(body));
          if (resource === "persistentvolumeclaims") {
            created.status = { phase: "Pending" };
          }
          return ok(structuredClone(created));
        }
        case "patch": {
          const [, resource, name] = args;
          const object = get(resource, namespace, name);
          if (object === undefined) {
            return { status: 1, stdout: "", stderr: `${name} not found` };
          }
          const patch = JSON.parse(flag(args, "-p"));
          let next;
          if (flag(args, "--type") === "json") {
            next = structuredClone(object);
            for (const { op, path, value } of patch) {
              assert.equal(path, "/spec/claimRef");
              assert.ok(op === "replace" || op === "add");
              next.spec.claimRef = value;
            }
          } else {
            next = mergePatch(object, patch);
          }
          if (resource === "deployments.apps" && next.spec.replicas !== undefined) {
            next.status = { replicas: next.spec.replicas };
            if (next.spec.replicas === 0) {
              for (const pod of items("pods", next.metadata.namespace)) {
                if (pod.metadata.labels?.app === name) {
                  store.delete(key("pods", pod.metadata.namespace, pod.metadata.name));
                }
              }
            }
          }
          return ok(structuredClone(put(resource, next)));
        }
        case "delete": {
          assert.equal(args[1], "--raw");
          const { preconditions } = JSON.parse(input);
          const parts = args[2].split("/").filter(Boolean);
          const name = parts.at(-1);
          const plural = parts.at(-2);
          const resource = Object.keys(RESOURCES).find((entry) => entry.split(".")[0] === plural);
          const objectNamespace =
            parts.includes("namespaces") && plural !== "namespaces"
              ? parts[parts.indexOf("namespaces") + 1]
              : undefined;
          const object = get(resource, objectNamespace, name);
          if (object === undefined) {
            return { status: 1, stdout: "", stderr: "NotFound" };
          }
          if (object.metadata.uid !== preconditions.uid) {
            return { status: 1, stdout: "", stderr: "Conflict: precondition failed" };
          }
          remove(resource, object);
          return ok(undefined);
        }
        default:
          throw new Error(`unexpected kubectl ${args.join(" ")}`);
      }
    } finally {
      reconcile();
    }
  };
  return { store, put, get, items, calls, failures, run, kubectl: createKubectl(run) };
}

const id = "ns_11111111-1111-4111-8111-111111111111";
const storage = storageNamespaceName(id);
const tenantNamespace = `oce-${createHash("sha256").update(id).digest("hex").slice(0, 15)}`;
const digest = (value) => createHash("sha256").update(value).digest("hex").slice(0, 12);
const dedicated = digest("agent-dedicated");
const embedded = digest("agent-embedded");
const owned = (agent) => ({
  labels: {
    "app.kubernetes.io/managed-by": "openclaw-enterprise",
    "openclaw.dev/namespace": id,
    ...(agent === undefined ? {} : { "openclaw.dev/agent": agent }),
  },
  annotations: {
    "openclaw.dev/namespace-id": id,
    ...(agent === undefined ? {} : { "openclaw.dev/agent-id": agent }),
  },
});

// A released single-cluster tenant: canonical storage and the dedicated Gateway in the storage
// namespace; the dedicated Harness, the embedded Agent, its transport Secret and routes in the
// Harness namespace.
function releasedInstallation({ reclaimPolicy = "Delete" } = {}) {
  const cluster = fakeCluster();
  const { put } = cluster;
  put("namespaces", {
    metadata: {
      name: storage,
      labels: {
        "app.kubernetes.io/managed-by": "openclaw-enterprise",
        "openclaw.dev/gateway-namespace": id,
      },
      annotations: { "openclaw.dev/namespace-id": id },
    },
    status: { phase: "Active" },
  });
  put("namespaces", {
    metadata: { name: tenantNamespace, ...owned() },
    status: { phase: "Active" },
  });
  for (const component of ["api", "worker"]) {
    put("deployments.apps", {
      metadata: { name: `openclaw-enterprise-${component}`, namespace: "openclaw-system" },
      spec: {
        replicas: 1,
        template: { spec: { containers: [{ image: "controller@sha256:released" }] } },
      },
      status: { replicas: 1 },
    });
  }
  for (const [role, account] of [
    ["oce-openclaw-tenant-worker", "openclaw-enterprise-worker"],
    ["oce-openclaw-tenant-api", "openclaw-enterprise-api"],
    ["oce-openclaw-tenant-configuration", "openclaw-enterprise-api"],
  ]) {
    for (const namespace of [storage, tenantNamespace]) {
      put("rolebindings.rbac.authorization.k8s.io", {
        metadata: { name: role.replace("oce-openclaw-tenant", "grant"), namespace },
        roleRef: { kind: "ClusterRole", name: role },
        subjects: [{ kind: "ServiceAccount", name: account, namespace: "openclaw-system" }],
      });
    }
  }
  const claim = (namespace, name, pv, agent, storageClassName) => {
    put("persistentvolumes", {
      metadata: { name: pv, annotations: { "test.example/data": `bytes of ${name}` } },
      spec: {
        persistentVolumeReclaimPolicy: reclaimPolicy,
        storageClassName,
        claimRef: { kind: "PersistentVolumeClaim", namespace, name, uid: `claim-${pv}` },
      },
      status: { phase: "Bound" },
    });
    put("persistentvolumeclaims", {
      metadata: {
        name,
        namespace,
        uid: `claim-${pv}`,
        ...owned(agent),
        annotations: {
          ...owned(agent).annotations,
          "pv.kubernetes.io/bind-completed": "yes",
        },
      },
      spec: {
        accessModes: ["ReadWriteOnce"],
        resources: { requests: { storage: "1Gi" } },
        volumeMode: "Filesystem",
        storageClassName,
        volumeName: pv,
      },
      status: { phase: "Bound" },
    });
  };
  // Canonical state that adoption must leave untouched.
  claim(
    storage,
    `gateway-state-${dedicated}`,
    "pv-dedicated-gateway",
    "agent-dedicated",
    "local-path",
  );
  put("secrets", {
    metadata: {
      name: "occ-model-key",
      namespace: storage,
      uid: "canonical-secret-uid",
      ...owned(),
    },
    type: "Opaque",
    data: { value: "c2VjcmV0" },
  });
  put("deployments.apps", {
    metadata: { name: `gateway-${dedicated}`, namespace: storage, ...owned("agent-dedicated") },
    spec: { replicas: 1 },
    status: { replicas: 1 },
  });
  // The Harness namespace.
  claim(
    tenantNamespace,
    `workspace-${dedicated}`,
    "pv-dedicated-workspace",
    "agent-dedicated",
    "local-path",
  );
  claim(
    tenantNamespace,
    `gateway-state-${embedded}`,
    "pv-embedded-state",
    "agent-embedded",
    "local-path",
  );
  for (const [name, agent] of [
    [`agent-${dedicated}`, "agent-dedicated"],
    [`gateway-${embedded}`, "agent-embedded"],
  ]) {
    put("deployments.apps", {
      metadata: { name, namespace: tenantNamespace, ...owned(agent) },
      spec: { replicas: 1 },
      status: { replicas: 1 },
    });
    put("pods", {
      metadata: { name: `${name}-pod`, namespace: tenantNamespace, labels: { app: name } },
      spec: {
        volumes: [
          {
            name: "state",
            persistentVolumeClaim: {
              claimName: name.startsWith("agent-")
                ? `workspace-${dedicated}`
                : `gateway-state-${embedded}`,
            },
          },
        ],
      },
    });
  }
  put("secrets", {
    metadata: {
      name: `transport-${embedded}`,
      namespace: tenantNamespace,
      ...owned("agent-embedded"),
    },
    type: "Opaque",
    data: { "app-server-token": "dG9rZW4=", "gateway-password": "cGFzc3dvcmQ=" },
  });
  put("secrets", {
    metadata: {
      name: `gateway-secrets-${embedded}-${digest("revision-1")}`,
      namespace: tenantNamespace,
      ...owned("agent-embedded"),
    },
    type: "Opaque",
    data: { MODEL: "c2VjcmV0" },
  });
  put("configmaps", {
    metadata: {
      name: `plugins-${embedded}`,
      namespace: tenantNamespace,
      ...owned("agent-embedded"),
    },
    data: {},
  });
  put("configmaps", {
    metadata: { name: "kube-root-ca.crt", namespace: tenantNamespace },
    data: {},
  });
  put("serviceaccounts", { metadata: { name: "default", namespace: tenantNamespace } });
  put("services", {
    metadata: {
      name: `gateway-${embedded}`,
      namespace: tenantNamespace,
      uid: "service-uid",
      ...owned("agent-embedded"),
    },
  });
  put("httproutes.gateway.networking.k8s.io", {
    metadata: {
      name: `gateway-${embedded}`,
      namespace: tenantNamespace,
      ...owned("agent-embedded"),
      ownerReferences: [
        { apiVersion: "v1", kind: "Service", name: `gateway-${embedded}`, uid: "service-uid" },
      ],
    },
    spec: { hostnames: ["agent.example.test"] },
  });
  put("securitypolicies.gateway.envoyproxy.io", {
    metadata: {
      name: `gateway-${embedded}`,
      namespace: tenantNamespace,
      ...owned("agent-embedded"),
    },
    spec: {},
  });
  return cluster;
}

async function withArchive(t) {
  const archive = await mkdtemp(join(tmpdir(), "split-layout-adopt-"));
  t.after(() => rm(archive, { recursive: true, force: true }));
  return archive;
}

const fast = { sleep: async () => {}, timeoutMs: 50 };

function snapshot({ get }) {
  const volume = (name) => get("persistentvolumes", undefined, name);
  return {
    volumes: ["pv-dedicated-gateway", "pv-dedicated-workspace", "pv-embedded-state"].map(
      (name) => ({
        name,
        data: volume(name)?.metadata.annotations["test.example/data"],
        reclaim: volume(name)?.spec.persistentVolumeReclaimPolicy,
      }),
    ),
    canonicalSecretUid: get("secrets", storage, "occ-model-key")?.metadata.uid,
  };
}

test("plan sorts the Harness namespace into moved, copied, archived and dropped objects", () => {
  const { kubectl, calls } = releasedInstallation();
  const { plans, adopted } = planAll(kubectl);
  assert.deepEqual(adopted, []);
  assert.equal(plans.length, 1);
  const [plan] = plans;
  assert.equal(plan.storage, storage);
  assert.equal(plan.tenant, tenantNamespace);
  assert.deepEqual(plan.refusals, []);
  assert.deepEqual(plan.claims.sort(), [`gateway-state-${embedded}`, `workspace-${dedicated}`]);
  // Only Agent Secrets are copied; per-revision projections render again on the next deploy.
  assert.deepEqual(plan.secrets, [`transport-${embedded}`]);
  assert.deepEqual(plan.routes.map(({ resource }) => resource).sort(), [
    "httproutes.gateway.networking.k8s.io",
    "securitypolicies.gateway.envoyproxy.io",
  ]);
  assert.deepEqual(plan.running, ["agent-dedicated", "agent-embedded"]);
  // Planning is read-only.
  assert.equal(
    calls.some((call) => /^(create|patch|delete) /u.test(call)),
    false,
  );
});

test("apply adopts the storage namespace, moves claims by rebind and finalize removes the old namespace", async (t) => {
  const archive = await withArchive(t);
  const cluster = releasedInstallation();
  const { kubectl, get, items } = cluster;
  const before = snapshot(cluster);
  const transport = structuredClone(get("secrets", tenantNamespace, `transport-${embedded}`));

  await applyAdoption(kubectl, { archive, ...fast });

  // OCC stays stopped for the upgrade helper, which accepts zero replicas.
  for (const component of ["api", "worker"]) {
    assert.equal(
      get("deployments.apps", "openclaw-system", `openclaw-enterprise-${component}`).spec.replicas,
      0,
    );
  }
  assert.equal(get("namespaces", undefined, storage).metadata.labels["openclaw.dev/namespace"], id);
  assert.equal(
    get("namespaces", undefined, tenantNamespace).metadata.labels["openclaw.dev/namespace"],
    undefined,
  );
  // Each claim keeps its volume, data and reclaim policy, now in the adopted namespace.
  for (const [name, pv] of [
    [`workspace-${dedicated}`, "pv-dedicated-workspace"],
    [`gateway-state-${embedded}`, "pv-embedded-state"],
  ]) {
    const claim = get("persistentvolumeclaims", storage, name);
    assert.equal(claim.status.phase, "Bound");
    assert.equal(claim.spec.volumeName, pv);
    assert.equal(claim.spec.storageClassName, "local-path");
    assert.equal(claim.metadata.labels["openclaw.dev/agent"] !== undefined, true);
    assert.equal(claim.metadata.annotations["pv.kubernetes.io/bind-completed"], undefined);
    assert.equal(get("persistentvolumeclaims", tenantNamespace, name), undefined);
    assert.equal(get("persistentvolumes", undefined, pv).spec.claimRef.uid, claim.metadata.uid);
  }
  assert.deepEqual(snapshot(cluster), before);
  // The embedded transport Secret is copied byte for byte with its ownership metadata.
  const copied = get("secrets", storage, `transport-${embedded}`);
  assert.deepEqual(copied.data, transport.data);
  assert.deepEqual(copied.metadata.labels, transport.metadata.labels);
  assert.notEqual(copied.metadata.uid, transport.metadata.uid);
  assert.equal(
    get("secrets", storage, `gateway-secrets-${embedded}-${digest("revision-1")}`),
    undefined,
  );
  // Stale routes would shadow the ones the new release renders, so they leave with an archive.
  assert.deepEqual(items("httproutes.gateway.networking.k8s.io", tenantNamespace), []);
  assert.deepEqual(items("securitypolicies.gateway.envoyproxy.io", tenantNamespace), []);
  const routesFile = join(archive, id, "routes.json");
  assert.equal((await stat(routesFile)).mode & 0o777, 0o600);
  assert.equal(JSON.parse(await readFile(routesFile, "utf8")).length, 2);
  // Canonical storage and the dedicated Gateway were not touched.
  assert.equal(get("deployments.apps", storage, `gateway-${dedicated}`).spec.replicas, 1);
  const journal = JSON.parse(
    get("namespaces", undefined, storage).metadata.annotations[JOURNAL_ANNOTATION],
  );
  assert.equal(journal.state, "applied");
  assert.deepEqual(journal.running, ["agent-dedicated", "agent-embedded"]);

  // A second apply has nothing left to do.
  assert.deepEqual(await applyAdoption(kubectl, { archive, ...fast }), []);
  await assert.rejects(finalizeAdoption(kubectl, fast), /upgrade the controller first/);

  // The upgrade helper starts the new release.
  for (const component of ["api", "worker"]) {
    const writer = get("deployments.apps", "openclaw-system", `openclaw-enterprise-${component}`);
    writer.spec.template.spec.containers[0].image = "controller@sha256:current";
    writer.spec.replicas = 1;
  }
  await assert.rejects(
    revertAdoption(kubectl, { archive, ...fast }),
    /revert is only possible before/,
  );
  await finalizeAdoption(kubectl, fast);
  assert.equal(get("namespaces", undefined, tenantNamespace), undefined);
  assert.equal(
    get("namespaces", undefined, storage).metadata.annotations[JOURNAL_ANNOTATION],
    undefined,
  );
  // Deleting the old namespace released no data: every volume moved before it went.
  assert.deepEqual(snapshot(cluster), before);
});

test("revert before the upgrade restores the released layout exactly", async (t) => {
  const archive = await withArchive(t);
  const cluster = releasedInstallation();
  const { kubectl, get, items } = cluster;
  const before = snapshot(cluster);
  const claimsBefore = items("persistentvolumeclaims", tenantNamespace)
    .map(({ metadata, spec }) => [metadata.name, spec.volumeName])
    .sort();

  await applyAdoption(kubectl, { archive, ...fast });
  await revertAdoption(kubectl, { archive, ...fast });

  assert.equal(
    get("namespaces", undefined, storage).metadata.labels["openclaw.dev/namespace"],
    undefined,
  );
  assert.equal(
    get("namespaces", undefined, tenantNamespace).metadata.labels["openclaw.dev/namespace"],
    id,
  );
  assert.equal(
    get("namespaces", undefined, storage).metadata.annotations[JOURNAL_ANNOTATION],
    undefined,
  );
  assert.deepEqual(
    items("persistentvolumeclaims", tenantNamespace)
      .map(({ metadata, spec, status }) => [metadata.name, spec.volumeName, status.phase])
      .sort(),
    claimsBefore.map((entry) => [...entry, "Bound"]),
  );
  assert.deepEqual(snapshot(cluster), before);
  assert.equal(get("secrets", storage, `transport-${embedded}`), undefined);
  const route = get("httproutes.gateway.networking.k8s.io", tenantNamespace, `gateway-${embedded}`);
  assert.deepEqual(route.spec, { hostnames: ["agent.example.test"] });
  assert.equal(route.metadata.ownerReferences[0].uid, "service-uid");
  assert.equal(items("securitypolicies.gateway.envoyproxy.io", tenantNamespace).length, 1);
  for (const name of [`agent-${dedicated}`, `gateway-${embedded}`]) {
    assert.equal(get("deployments.apps", tenantNamespace, name).spec.replicas, 1);
  }
  for (const component of ["api", "worker"]) {
    assert.equal(
      get("deployments.apps", "openclaw-system", `openclaw-enterprise-${component}`).spec.replicas,
      1,
    );
  }
});

test("an interrupted rebind resumes without releasing the volume", async (t) => {
  const archive = await withArchive(t);
  const cluster = releasedInstallation({ reclaimPolicy: "Delete" });
  const { kubectl, get, failures } = cluster;
  const before = snapshot(cluster);
  // The old claim is gone and the new one not yet created when the run dies. With the
  // release's Delete policy this is the moment a missing Retain step would lose the data.
  failures.push(
    (args, input) => args[0] === "create" && JSON.parse(input).kind === "PersistentVolumeClaim",
  );
  await assert.rejects(applyAdoption(kubectl, { archive, ...fast }), /injected failure/);
  const journal = JSON.parse(
    get("namespaces", undefined, storage).metadata.annotations[JOURNAL_ANNOTATION],
  );
  assert.equal(journal.state, "applying");
  assert.equal(
    get("namespaces", undefined, storage).metadata.labels["openclaw.dev/namespace"],
    undefined,
  );

  await applyAdoption(kubectl, { archive, ...fast });
  assert.equal(
    JSON.parse(get("namespaces", undefined, storage).metadata.annotations[JOURNAL_ANNOTATION])
      .state,
    "applied",
  );
  assert.deepEqual(snapshot(cluster), before);
  // The replicas recorded before the first stop survive the resumed run.
  assert.equal(journal.writers.api.replicas, 1);
});

test("a claim mid-move survives a crash and still binds on the next run", async (t) => {
  const archive = await withArchive(t);
  const cluster = releasedInstallation();
  const { kubectl, get, failures } = cluster;
  const before = snapshot(cluster);
  // The old claim is deleted and its volume Released, still referencing the deleted claim.
  failures.push((args) => args[0] === "patch" && args[args.indexOf("--type") + 1] === "json");
  await assert.rejects(applyAdoption(kubectl, { archive, ...fast }), /injected failure/);
  assert.equal(
    get("persistentvolumes", undefined, "pv-dedicated-workspace").status.phase,
    "Released",
  );
  await applyAdoption(kubectl, { archive, ...fast });
  assert.deepEqual(snapshot(cluster), before);
  assert.equal(
    get("persistentvolumeclaims", storage, `workspace-${dedicated}`).status.phase,
    "Bound",
  );
});

test("a Pod that keeps mounting a claim stops apply before the claim is deleted", async (t) => {
  const archive = await withArchive(t);
  const cluster = releasedInstallation();
  const { kubectl, put, get } = cluster;
  put("pods", {
    metadata: { name: "debug", namespace: tenantNamespace },
    spec: {
      volumes: [{ name: "w", persistentVolumeClaim: { claimName: `workspace-${dedicated}` } }],
    },
  });
  await assert.rejects(
    applyAdoption(kubectl, { archive, ...fast }),
    /Pods in .* to release their claims/,
  );
  assert.equal(
    get("persistentvolumeclaims", tenantNamespace, `workspace-${dedicated}`).metadata
      .deletionTimestamp,
    undefined,
  );
  // Revert brings the old release back even from this early stop.
  await revertAdoption(kubectl, { archive, ...fast });
  assert.equal(
    get("deployments.apps", "openclaw-system", "openclaw-enterprise-api").spec.replicas,
    1,
  );
});

test("plan refuses tenants adoption cannot carry, and apply then changes nothing", async (t) => {
  const archive = await withArchive(t);
  const cases = [
    [
      "an existing (external) tenant namespace",
      ({ get }) => {
        get("namespaces", undefined, tenantNamespace).metadata.annotations[
          "openclaw.dev/namespace-lifecycle"
        ] = "external";
      },
      /split-layout-tenants\.mjs/,
    ],
    [
      "an object OCE does not manage",
      ({ put }) =>
        put("configmaps", { metadata: { name: "operator-notes", namespace: tenantNamespace } }),
      /configmaps\/operator-notes/,
    ],
    [
      "a claim OCE does not move",
      ({ put }) =>
        put("persistentvolumeclaims", {
          metadata: { name: "scratch", namespace: tenantNamespace, ...owned() },
          spec: {},
          status: { phase: "Pending" },
        }),
      /persistentvolumeclaims\/scratch/,
    ],
    [
      "a claim name already used in the storage namespace",
      ({ put }) =>
        put("persistentvolumeclaims", {
          metadata: { name: `workspace-${dedicated}`, namespace: storage, ...owned() },
          spec: { volumeName: "other" },
          status: { phase: "Bound" },
        }),
      /already has PersistentVolumeClaim/,
    ],
    [
      "a different Secret under the same name",
      ({ put }) =>
        put("secrets", {
          metadata: {
            name: `transport-${embedded}`,
            namespace: storage,
            ...owned("agent-embedded"),
          },
          type: "Opaque",
          data: { "app-server-token": "b3RoZXI=" },
        }),
      /different Secret/,
    ],
    [
      "a missing storage grant",
      ({ store }) => store.delete(`rolebindings.rbac.authorization.k8s.io/${storage}/grant-api`),
      /lacks a RoleBinding of ClusterRole \*-openclaw-tenant-api/,
    ],
    [
      "no tenant namespace in this cluster",
      ({ store }) => store.delete(`namespaces//${tenantNamespace}`),
      /two-cluster control target/,
    ],
    [
      "a terminating tenant namespace",
      ({ get }) => {
        get("namespaces", undefined, tenantNamespace).metadata.deletionTimestamp =
          "2026-10-09T00:00:00Z";
      },
      /terminating/,
    ],
  ];
  for (const [description, mutate, expected] of cases) {
    const cluster = releasedInstallation();
    mutate(cluster);
    const [plan] = planAll(cluster.kubectl).plans;
    assert.match(plan.refusals.join("\n"), expected, description);
    const calls = cluster.calls.length;
    await assert.rejects(applyAdoption(cluster.kubectl, { archive, ...fast }), AdoptError);
    assert.equal(
      cluster.calls.slice(calls).some((call) => /^(create|patch|delete) /u.test(call)),
      false,
      `${description}: apply must refuse before any change`,
    );
  }
});

test("an already shared or adopted tenant and another tenant's storage name are left alone", () => {
  const cluster = releasedInstallation();
  const { put, get } = cluster;
  get("namespaces", undefined, storage).metadata.labels["openclaw.dev/namespace"] = id;
  put("namespaces", {
    metadata: {
      name: "oce-shared",
      labels: {
        "openclaw.dev/gateway-namespace": "ns_other",
        "openclaw.dev/namespace": "ns_other",
      },
    },
  });
  assert.deepEqual(planAll(cluster.kubectl), { plans: [], adopted: [] });
});
