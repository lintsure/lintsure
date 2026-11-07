// What the agents know about each framework, written in Lintsure's own words.
// Rule of the house: no quoted text from standards or regulators. ISO and AICPA texts are
// licensed; we only reference their control IDs (facts) and describe intent in plain English.
import type { FrameworkId } from "../types.js";

/** Answers the Classifier asks for (or infers from code, then asks you to confirm). */
export interface Profile {
  /** Do you offer the product to people in the EU or EEA, or monitor them? */
  euUsers?: boolean;
  /** Does the code handle data about identifiable people? */
  personalData?: boolean;
  /** Health, biometric, ethnicity, religion, sexual life, political views, union membership. */
  specialCategoryData?: boolean;
  /** Does your product use or include an AI system? */
  usesAI?: boolean;
  /** Does it generate text, images, audio or video? */
  generativeAI?: boolean;
  /** Does it chat or talk with people directly? */
  interactsWithPeople?: boolean;
  /** Does it help decide something important about a person? */
  decisionArea?: "none" | "credit" | "employment" | "education" | "essential-services" | "insurance" | "biometrics" | "law-enforcement" | "migration" | "justice" | "critical-infrastructure";
  /** Do business customers ask you for security proof? */
  b2bCustomers?: boolean;
  /** Do customers or partners ask specifically for an ISO certificate? */
  wantsCertification?: boolean;
  /** Are you based in, or mainly selling to, the US? */
  usMarket?: boolean;
}

export interface Obligation {
  /** Article, criterion or Annex A control ID. */
  ref: string;
  title: string;
  /** What it asks of you, in plain words. */
  plain: string;
  /** Can code show it? "yes" = rules check it. "partly" = code shows signals. "no" = Outside code. */
  inCode: "yes" | "partly" | "no";
  /** Lintsure rule ids that check it. */
  rules?: string[];
  /** For inCode "no"/"partly": what an auditor will ask to see. */
  evidence?: string;
}

export interface Milestone { date: string; what: string }

export interface FrameworkKnowledge {
  id: FrameworkId;
  name: string;
  kind: "law" | "standard" | "attestation";
  /** One paragraph a founder can read in 30 seconds. */
  summary: string;
  /** Who it applies to, in plain words. */
  whoItAppliesTo: string;
  /** Classifier: returns a reason when it likely applies, null when it likely doesn't. */
  applies(p: Profile): string | null;
  /** Key dates, newest rules included. */
  timeline?: Milestone[];
  obligations: Obligation[];
  /** Things people often get wrong. */
  watchOut: string[];
  /** When the agents' knowledge was last checked against the source texts. */
  checkedOn: string;
}
