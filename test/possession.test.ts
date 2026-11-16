// Proof of possession (Piano A, 15/11): a copied mandate is not enough; the agent must sign a fresh challenge.

import { test } from "node:test";
import assert from "node:assert/strict";
import { answerChallenge, createMandate, mandateId, generateKeyPair, newChallenge, possessionProblem, signValue, type Mandate } from "../src/index.js";

const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

function agentWithMandate() {
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const mandate: Mandate = createMandate(owner, { ownerDomain: "shop.example", agent: agent.publicKey, scope: "sales", notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" });
  return { owner, agent, mandate };
}

test("the real agent answers the challenge and passes", () => {
  const { agent, mandate } = agentWithMandate();
  const checker = generateKeyPair();
  const c = newChallenge();
  const answer = answerChallenge(agent, mandate, c.challenge, { for: checker.publicKey });
  assert.equal(possessionProblem(mandate, answer, c.challenge, { for: checker.publicKey }), null);
  assert.equal(possessionProblem(mandate, answer, c.challenge), null, "without 'for' the checker accepts any addressee");
});

test("someone who only copied the mandate cannot answer", () => {
  const { mandate } = agentWithMandate();
  const thief = generateKeyPair();
  const c = newChallenge();
  assert.throws(() => answerChallenge(thief, mandate, c.challenge), /another agent key/);
  // A hand-made answer that names the real agent and mandate, but is signed by the thief.
  const body = { type: "symbolon/possession" as const, v: 1 as const, challenge: c.challenge, agent: mandate.body.agent, mandate: mandateId(mandate), at: new Date().toISOString() };
  assert.match(String(possessionProblem(mandate, { body, signature: signValue(body, thief) }, c.challenge)), /signature/);
});

test("old, replayed, redirected or foreign answers are refused", () => {
  const { agent, mandate } = agentWithMandate();
  const other = agentWithMandate();
  const checker = generateKeyPair();
  const c1 = newChallenge();
  const c2 = newChallenge();
  const a1 = answerChallenge(agent, mandate, c1.challenge, { for: checker.publicKey });
  assert.match(String(possessionProblem(mandate, a1, c2.challenge)), /another challenge/, "an answer to an earlier challenge cannot be replayed");
  assert.match(String(possessionProblem(mandate, a1, c1.challenge, { for: generateKeyPair().publicKey })), /someone else/);
  assert.match(String(possessionProblem(other.mandate, a1, c1.challenge)), /another agent/);
  const old = answerChallenge(agent, mandate, c1.challenge, { now: new Date(Date.now() - 10 * 60_000) });
  assert.match(String(possessionProblem(mandate, old, c1.challenge)), /too old/);
  const tampered = { ...a1, body: { ...a1.body, at: new Date(Date.now() + 1000).toISOString() } };
  assert.match(String(possessionProblem(mandate, tampered, c1.challenge)), /signature/);
  assert.match(String(possessionProblem(mandate, { ...a1, extra: 1 }, c1.challenge)), /unexpected/);
  assert.match(String(possessionProblem(mandate, "nope", c1.challenge)), /not a possession/);
  assert.throws(() => answerChallenge(agent, mandate, "short"), /64 lowercase hex/);
});
