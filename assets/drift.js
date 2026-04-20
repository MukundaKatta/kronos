/**
 * Kronos — infrastructure drift helpers.
 *
 * Compares a *desired* state (from IaC: Terraform, Pulumi, Crossplane)
 * against an *observed* state (from the cloud provider's live inventory)
 * and produces a structured drift report suitable for the dashboard.
 *
 * Kept dependency-free so it runs in the static bundle next to the
 * report viewer.
 */

/**
 * Recursive deep-diff that treats arrays as ordered sequences but
 * primitive objects as sets of keys. Returns an array of change
 * records with `path`, `kind`, and `before/after`.
 */
export function diffResources(desired, observed, { path = [] } = {}) {
  const changes = [];
  const seen = new Set();

  for (const key of Object.keys(desired || {})) {
    seen.add(key);
    const here = [...path, key];
    if (!(key in (observed || {}))) {
      changes.push({ path: here.join("."), kind: "removed", before: desired[key], after: undefined });
      continue;
    }
    changes.push(...diffValue(desired[key], observed[key], here));
  }
  for (const key of Object.keys(observed || {})) {
    if (seen.has(key)) continue;
    const here = [...path, key];
    changes.push({ path: here.join("."), kind: "added", before: undefined, after: observed[key] });
  }
  return changes;
}

function diffValue(a, b, path) {
  if (a === b) return [];
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) {
      return [{ path: path.join("."), kind: "changed", before: a, after: b }];
    }
    const out = [];
    for (let i = 0; i < a.length; i++) {
      out.push(...diffValue(a[i], b[i], [...path, i]));
    }
    return out;
  }
  if (isObj(a) && isObj(b)) return diffResources(a, b, { path });
  return [{ path: path.join("."), kind: "changed", before: a, after: b }];
}

function isObj(v) {
  return v && typeof v === "object" && !Array.isArray(v);
}

/**
 * Classify drift urgency. Security-group / IAM changes are always high;
 * tag-only drift is noise.
 */
export function classifyDrift(change) {
  const p = change.path.toLowerCase();
  if (p.includes("iam") || p.includes("policy") || p.includes("securitygroup") || p.includes("security_group")) {
    return { severity: "high", note: "security-surface change" };
  }
  if (p.endsWith("tags") || p.includes(".tags.") || p.includes("description")) {
    return { severity: "low", note: "metadata-only drift" };
  }
  if (change.kind === "removed") {
    return { severity: "high", note: "resource or field removed from live state" };
  }
  return { severity: "medium", note: "configuration drift" };
}

/**
 * Roll a change list up into counters suitable for the summary card.
 */
export function summarize(changes) {
  const out = { total: changes.length, high: 0, medium: 0, low: 0, byKind: {} };
  for (const c of changes) {
    const { severity } = classifyDrift(c);
    out[severity]++;
    out.byKind[c.kind] = (out.byKind[c.kind] || 0) + 1;
  }
  return out;
}

/**
 * Baseline drift policy for how findings are categorized.
 */
export function createDriftBaseline() {
  return {
    informational: ["tags", "descriptions"],
    actionable: ["scaling", "networking", "runtime"],
    dangerous: ["iam", "policy", "securitygroup", "security_group"],
  };
}

/**
 * Approval and remediation lifecycle for a drift finding.
 */
export function remediationWorkflow(change) {
  const severity = classifyDrift(change).severity;
  return {
    state: severity === "low" ? "detected" : "awaiting-approval",
    approvalRequired: severity !== "low",
    autoRemediate: severity === "low",
    exceptionAllowed: true,
  };
}

/**
 * Track intentional exceptions separately from remediation.
 */
export function createExceptionRecord(change, { owner, expiresAt, reason }) {
  return {
    path: change.path,
    owner,
    expiresAt,
    reason,
    state: "accepted-exception",
  };
}
