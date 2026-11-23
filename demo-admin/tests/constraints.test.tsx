import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ConstraintSummary, LimitValues } from "../src/features/agents/LimitValues.tsx";
import { normalizeConstraints } from "../src/api/client.ts";
import { buildConstraints, delegationPayload, describeConstraints, factsFor } from "../src/lib/constraints.ts";

const base = { agentId: "a", capabilityId: "c", resourceId: "r" };

test("payload omits constraints when no key has values", () => {
  assert.deepEqual(delegationPayload(base), base);
  const blank = buildConstraints([{ key: "", text: "" }, { key: "  ", text: " \n " }]);
  assert.deepEqual(blank, { ok: true });
  assert.ok(!("constraints" in delegationPayload(base, blank.ok ? blank.constraints : undefined)));
});

test("payload carries value_in with trimmed lines and empty lines dropped", () => {
  const built = buildConstraints([{ key: "gmail.recipients", text: " a@x.com \r\n\n b@x.com\n" }]);
  assert.ok(built.ok);
  assert.deepEqual(delegationPayload(base, built.ok ? built.constraints : undefined), { ...base, constraints: { value_in: { "gmail.recipients": ["a@x.com", "b@x.com"] } } });
});

test("client validation rejects bad keys, empty lists, duplicates, control characters and too many values", () => {
  const bad = (rows: { key: string; text: string }[]) => assert.equal(buildConstraints(rows).ok, false);
  for (const key of ["Gmail.recipients", "1abc", "a..b", "a.b.c.d.e.f", "a-b", "gmail.", ""]) bad([{ key, text: "v" }]);
  bad([{ key: "a.b", text: "  \n " }]);
  bad([{ key: "a.b", text: "x\ny\nx" }]);
  bad([{ key: "a.b", text: "x\u0007y" }]);
  bad([{ key: "a.b", text: "x\ty" }]);
  bad([{ key: "a.b", text: "x".repeat(513) }]);
  bad([{ key: "a.b", text: Array.from({ length: 201 }, (_, i) => `v${i}`).join("\n") }]);
  bad([{ key: "a.b", text: "x" }, { key: "a.b", text: "y" }]);
  bad(Array.from({ length: 21 }, (_, i) => ({ key: `k${i}`, text: "v" })));
  assert.equal(buildConstraints([{ key: "a.b", text: "x".repeat(512) }]).ok, true);
  assert.equal(buildConstraints([{ key: "a.b", text: Array.from({ length: 200 }, (_, i) => `v${i}`).join("\n") }]).ok, true);
  assert.equal(buildConstraints(Array.from({ length: 20 }, (_, i) => ({ key: `k${i}`, text: "v" }))).ok, true);
});

test("constraints render as escaped text and long lists collapse to five plus a count", () => {
  const html = renderToStaticMarkup(<ConstraintSummary constraints={{ value_in: { "gmail.recipients": ["<img src=x onerror=alert(1)>"] } }} />);
  assert.match(html, /Limited to: /);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(html, /<img/);
  assert.deepEqual(describeConstraints({ value_in: { k: ["1", "2", "3", "4", "5", "6", "7"] } }), ["k ∈ {1, 2, 3, 4, 5, and 2 more}"]);
  assert.deepEqual(describeConstraints({ value_in: { k: ["1", "2", "3", "4", "5"] } }), ["k ∈ {1, 2, 3, 4, 5}"]);
  assert.deepEqual(describeConstraints(undefined), []);
  assert.equal(renderToStaticMarkup(<ConstraintSummary constraints={{}} />), "");
});

test("listing normalization accepts the server shape and tolerates empty constraints", () => {
  assert.deepEqual(normalizeConstraints({ value_in: { "a.b": ["x", 3] } }), { value_in: { "a.b": ["x"] } });
  assert.equal(normalizeConstraints({}), undefined);
  assert.equal(normalizeConstraints(undefined), undefined);
});

test("registry entries render as options beside the custom key choice", () => {
  const registry = { "Gmail.Message.Send": [{ key: "gmail.recipients", label: "Recipients", hint: "Allowed addresses" }] };
  const facts = factsFor(["Gmail.Message.Send", "Gmail.Message.Send", "Slack.Message.Read"], registry);
  assert.equal(facts.length, 1);
  const html = renderToStaticMarkup(<LimitValues rows={[{ key: "gmail.recipients", text: "" }]} onChange={() => undefined} facts={facts} />);
  assert.match(html, /<option value="gmail.recipients"[^>]*>Recipients<\/option>/);
  assert.match(html, /Advanced: custom key/);
  assert.match(html, /Allowed addresses/);
  assert.deepEqual(factsFor(["Slack.Message.Read"]), []);
});

test("an unknown key shows the custom input and validation errors", () => {
  const html = renderToStaticMarkup(<LimitValues rows={[{ key: "Bad Key", text: "v" }]} onChange={() => undefined} facts={[]} />);
  assert.match(html, /Custom key/);
  assert.match(html, /not a valid key/);
});

test("the default registry offers the Gmail recipients fact only for Google.Mail.Send", () => {
  const facts = factsFor(["Google.DriveFile.Read", "Google.Mail.Send"]);
  assert.deepEqual(facts, [{ key: "gmail.recipients", label: "Recipients the agent may email", hint: "One email address per line" }]);
  assert.deepEqual(factsFor(["Google.DriveFile.Read"]), []);
  const built = buildConstraints([{ key: "gmail.recipients", text: "a@example.com\nb@example.com" }]);
  assert.deepEqual(built, { ok: true, constraints: { value_in: { "gmail.recipients": ["a@example.com", "b@example.com"] } } });
});

test("the default registry offers the HubSpot deal property fact only for HubSpot.Deal.Update", () => {
  const facts = factsFor(["HubSpot.Deal.Read", "HubSpot.Deal.Update"]);
  assert.deepEqual(facts.map(fact => fact.key), ["hubspot.properties"]);
  assert.equal(facts[0].label, "Deal properties the agent may change");
  assert.deepEqual(factsFor(["HubSpot.Deal.Read", "HubSpot.Contact.Read"]), []);
  const built = buildConstraints([{ key: "hubspot.properties", text: "dealstage\namount" }]);
  assert.deepEqual(built, { ok: true, constraints: { value_in: { "hubspot.properties": ["dealstage", "amount"] } } });
});
