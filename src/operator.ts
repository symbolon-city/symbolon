// The operator kit ("automatic mode"). The operator is whoever runs agents for people (an assistant app,
// a platform, a developer) and answers for them in the city. It joins once; after that every request of
// a person ("translate this, at most 50 euros") becomes a task mandate signed by the operator's software,
// and the person never signs or sees anything.
//
//   owner key (kept safe, published at https://<domain>/.well-known/symbolon.json)
//     └─ issuing mandate, for a key on the operator's server, with a cap per agreement and an end date
//          └─ task mandate, one per request: the person's limits, a short validity, salted fingerprints
//             of the instruction and of the customer (no personal data in clear)
//
// If the server is breached the damage is capped by the issuing mandate, and one revocation of it stops
// every task mandate below. Runs on the operator's server, including a Cloudflare Worker.

import { generateKeyPair, keyPairFromSecret, type KeyPair, type PublicKey } from "./keys.js";
import { toHex } from "./bytes.js";
import { amountLeq, createMandate, createSubMandate, mandateId, taskCommitments, type Amount, type Mandate } from "./mandate.js";
import { createRevocation, type Revocation } from "./revocation.js";
import { ownerFile, type OwnerFile } from "./wellknown.js";

export interface OperatorSetup {
  /** Keep offline (password manager, paper): it signs only the issuing mandate and emergency revocations. */
  ownerSecretHex: string;
  /** Publish as https://<domain>/.well-known/symbolon.json (a free GitHub Pages site works: name.github.io). */
  ownerFile: OwnerFile;
  /** Store on the operator's server (as a secret): it signs the task mandates. */
  issuerSecretHex: string;
  issuingMandate: Mandate;
}

/** One-time setup: an owner key, the file to publish, a server key and its issuing mandate. */
export function setupOperator(o: {
  domain: string;
  /** Cap per agreement for any task (e.g. 500 EUR). Required: every chain starts with a money cap. */
  capPerAgreement: Amount;
  /** How long the issuing mandate lasts (default 90 days); renew it with a new one before it ends. */
  days?: number;
  ownerSecretHex?: string;
  now?: Date;
}): OperatorSetup {
  if (!o.capPerAgreement) throw new Error("capPerAgreement is required: every task needs a money cap from above");
  const now = o.now ?? new Date();
  const owner = o.ownerSecretHex ? keyPairFromSecret(o.ownerSecretHex) : generateKeyPair();
  const issuer = generateKeyPair();
  const issuingMandate = createMandate(owner, {
    ownerDomain: o.domain,
    agent: issuer.publicKey,
    scope: `issues task mandates for the agents that ${o.domain} runs for its customers`,
    maxAmount: o.capPerAgreement,
    notBefore: new Date(now.getTime() - 60_000).toISOString(),
    notAfter: new Date(now.getTime() + (o.days ?? 90) * 86_400_000).toISOString(),
    charter: "accord-charter/0.1",
  });
  return { ownerSecretHex: toHex(owner.secretKey), ownerFile: ownerFile(o.domain, [owner.publicKey]), issuerSecretHex: toHex(issuer.secretKey), issuingMandate };
}

/** A new task for an agent: its mandate, its key, and the salt that proves later which instruction and customer. */
export interface Task {
  mandate: Mandate;
  /** The task agent's key. Give it to the agent's wallet; never send it anywhere else. */
  agentSecretHex: string;
  /** Keep with the operator's own records (with the instruction and the customer id), never publish. */
  salt: string;
}

export type TaskRequest = {
  /** The person's words, as received. Only its salted fingerprint goes into the mandate. */
  instruction: string;
  /** The operator's own id for the customer. Only its salted fingerprint goes into the mandate. */
  principalId: string;
  /** What counterparties see about the task, in plain words, without personal data (default: a generic line). */
  scope?: string;
  /** Limit per agreement. */
  maxAmount?: Amount;
  /** Limit for the whole task (default: the operator's capPerTask). */
  total?: Amount;
  /** Validity in hours (default 24, at most the operator's maxTaskHours). */
  hours?: number;
  /** Set when the person confirmed an amount above the operator's confirmation threshold. */
  confirmed?: boolean;
  /** Give the task to an agent key that already exists (otherwise a fresh one is made). */
  agentKey?: PublicKey;
};

/** The operator's software. It decides limits with fixed rules: the AI's reading of a request never raises them. */
export class Operator {
  private readonly issuer: KeyPair;
  private issuedToday = new Map<string, number>();

  constructor(
    private readonly o: {
      issuerSecretHex: string;
      issuingMandate: Mandate;
      /** Above this (per agreement or total) the person must confirm once ("Confirm up to 300 EUR?"). */
      confirmAbove?: Amount;
      /** Hard cap per task, whatever the request says. Required: a task without amounts gets this as its total. */
      capPerTask: Amount;
      maxTaskHours?: number;
      /** At most this many task mandates a day (default 10,000). */
      tasksPerDay?: number;
      /**
       * Counts one more task for the day and returns the new count. The default counts in memory, which
       * restarts at zero with the process: on a server with several instances or restarts, pass a counter
       * kept in a shared store.
       */
      countTask?: (day: string) => number;
      now?: () => Date;
    },
  ) {
    this.issuer = keyPairFromSecret(o.issuerSecretHex);
    if (!o.capPerTask) throw new Error("capPerTask is required: every task needs a money cap");
    const pcap = o.issuingMandate.body.maxAmount;
    if (!pcap) throw new Error("the issuing mandate has no cap per agreement (maxAmount): make it with setupOperator");
    if (pcap.currency !== o.capPerTask.currency) throw new Error("capPerTask and the issuing mandate's cap must be in the same currency");
    if (o.issuingMandate.body.agent !== this.issuer.publicKey) throw new Error("the issuing mandate is for another key");
  }

  get domain(): string {
    // setupOperator always writes a domain: an operator answers for its customers' agents under its name.
    return this.o.issuingMandate.body.owner.domain ?? "";
  }

  private now() {
    return (this.o.now ?? (() => new Date()))();
  }

  /**
   * Turns a person's request into a task mandate. Returns `needsConfirmation` (and no mandate) when the
   * amount is above the confirmation threshold and the person has not confirmed yet.
   */
  newTask(r: TaskRequest): Task | { needsConfirmation: true; question: string } {
    const cap = this.o.capPerTask;
    const pcap = this.o.issuingMandate.body.maxAmount!;
    const over = (a: Amount | undefined, b: Amount | undefined) => !!a && !!b && (a.currency !== b.currency || !amountLeq(a.value, b.value));
    const min = (a: Amount, b: Amount) => (amountLeq(a.value, b.value) ? a : b);
    for (const a of [r.maxAmount, r.total]) if (over(a, cap)) throw new Error(`this operator allows at most ${cap.value} ${cap.currency} per task`);
    if (over(r.maxAmount, pcap)) throw new Error(`this operator allows at most ${pcap.value} ${pcap.currency} per agreement`);
    // The task always has a total (the request's, or the operator's cap) and a limit per agreement that is
    // never above the total nor the issuing mandate's cap.
    const total = r.total ?? cap;
    const perAgreement = min(min(r.maxAmount ?? total, total), pcap);
    // The person confirms whenever what the agent could spend (per agreement or in total) is above the threshold.
    if ((over(total, this.o.confirmAbove) || over(perAgreement, this.o.confirmAbove)) && !r.confirmed)
      return { needsConfirmation: true, question: `Confirm up to ${total.value} ${total.currency}?` };
    const day = this.now().toISOString().slice(0, 10);
    let n: number;
    if (this.o.countTask) n = this.o.countTask(day);
    else {
      n = (this.issuedToday.get(day) ?? 0) + 1;
      this.issuedToday = new Map([[day, n]]);
    }
    if (n > (this.o.tasksPerDay ?? 10_000)) throw new Error("daily limit of new tasks reached");
    const hours = Math.min(r.hours ?? 24, this.o.maxTaskHours ?? 24 * 7);
    const agent = r.agentKey ? null : generateKeyPair();
    const { task, salt } = taskCommitments(r.instruction, r.principalId);
    const parent = this.o.issuingMandate;
    const now = this.now().getTime();
    const mandate = createSubMandate(this.issuer, parent, {
      agent: r.agentKey ?? agent!.publicKey,
      scope: r.scope ?? `task for a customer of ${this.domain}`,
      maxAmount: perAgreement,
      total,
      notBefore: new Date(Math.max(now - 60_000, Date.parse(parent.body.notBefore))).toISOString(),
      notAfter: new Date(Math.min(now + hours * 3_600_000, Date.parse(parent.body.notAfter))).toISOString(),
      task,
    });
    return { mandate, agentSecretHex: agent ? toHex(agent.secretKey) : "", salt };
  }

  /** "Leave it": withdraws one task mandate (publish it to the register, e.g. with the register client's revoke). */
  cancelTask(task: Mandate, reason = "task cancelled"): Revocation {
    return createRevocation(this.issuer, { target: { kind: "mandate", id: mandateId(task) }, reason });
  }
}

/** Emergency: the owner withdraws the issuing mandate, and every task mandate below it stops at once. */
export function revokeIssuing(ownerSecretHex: string, issuingMandate: Mandate, reason = "issuing key withdrawn"): Revocation {
  return createRevocation(keyPairFromSecret(ownerSecretHex), { target: { kind: "mandate", id: mandateId(issuingMandate) }, reason });
}

/** For a dispute: proves which instruction and which customer a task mandate was for, given the kept salt. */
export function taskMatches(m: Mandate, instruction: string, principalId: string, salt: string): boolean {
  if (m.body.type !== "symbolon/submandate" || !m.body.task) return false;
  const { task } = taskCommitments(instruction, principalId, salt);
  return task.instruction === m.body.task.instruction && task.principal === m.body.task.principal;
}
