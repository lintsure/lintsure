import type { FrameworkKnowledge } from "./types.js";

// Own-words summary of Regulation (EU) 2016/679 (GDPR), informed by EDPB and national
// regulator guidance. Not legal advice.
export const gdpr: FrameworkKnowledge = {
  id: "gdpr",
  name: "GDPR",
  kind: "law",
  summary:
    "The EU's privacy law. If you handle data about people in the EU, you need a valid reason for each use, should collect only what you need, keep it safe, tell people what you do, and let them see, fix or delete their data. AI doesn't get special treatment: training on or feeding personal data into a model is still processing.",
  whoItAppliesTo:
    "Any organization that handles personal data while based in the EU, or that offers goods or services to people in the EU or tracks their behavior there.",
  timeline: [
    { date: "2018-05-25", what: "GDPR applies in full across the EU and EEA. There is no transition period left: every duty below applies today." },
  ],
  applies(p) {
    if (!p.personalData) return null;
    if (!p.euUsers) return null;
    return p.specialCategoryData
      ? "You handle personal data of people in the EU, including sensitive categories that need extra protection."
      : "You handle personal data of people in the EU.";
  },
  obligations: [
    { ref: "Art. 5", title: "Core principles", inCode: "partly", rules: ["pii.to-analytics", "pii.logged"],
      plain: "Use data fairly and openly, only for clear purposes, collect the minimum, keep it accurate, don't keep it longer than needed, and keep it secure.",
      evidence: "A retention schedule and a note on why each field is collected." },
    { ref: "Art. 6", title: "A lawful reason", inCode: "no",
      plain: "Every use of personal data needs one of six legal bases, such as consent, a contract, or legitimate interests weighed against people's rights.",
      evidence: "The legal basis recorded for each processing purpose." },
    { ref: "Art. 7", title: "Consent done right", inCode: "partly",
      plain: "If you rely on consent, it must be freely given, specific, informed and as easy to withdraw as to give. No pre-ticked boxes.",
      evidence: "Consent records and the wording users saw." },
    { ref: "Art. 9", title: "Sensitive data", inCode: "partly", rules: ["ai.emotion-or-biometric"],
      plain: "Health, biometric, ethnic, religious, political, sexual and union data is off-limits unless a specific exception applies.",
      evidence: "The exception you rely on." },
    { ref: "Art. 12–15", title: "Transparency and access", inCode: "no",
      plain: "Tell people clearly what you collect and why, and give them a copy of their data when they ask.",
      evidence: "Your privacy notice and how access requests are handled." },
    { ref: "Art. 17", title: "Right to erasure", inCode: "partly",
      plain: "When someone asks, and no exception applies, delete their data everywhere you hold it, including backups on rotation and third-party tools.",
      evidence: "The deletion path and where it reaches." },
    { ref: "Art. 22", title: "Automated decisions", inCode: "partly", rules: ["ai.automated-decision"],
      plain: "People have the right not to be subject to fully automated decisions with legal or similarly big effects, unless an exception applies and safeguards like human review are in place.",
      evidence: "The human review step and how people can contest a decision." },
    { ref: "Art. 25", title: "Privacy by design and default", inCode: "partly", rules: ["pii.in-url", "pii.to-analytics"],
      plain: "Build privacy in from the start, and make the most private setting the default.",
      evidence: "Design notes showing privacy choices." },
    { ref: "Art. 28", title: "Processors", inCode: "partly", rules: ["pii.to-analytics"],
      plain: "Vendors that handle personal data for you need a contract with specific data protection terms.",
      evidence: "Signed processing agreements with each vendor." },
    { ref: "Art. 30", title: "Records of processing", inCode: "no",
      plain: "Keep a list of what personal data you process, why, with whom you share it and how long you keep it.",
      evidence: "The register of processing activities." },
    { ref: "Art. 32", title: "Security of processing", inCode: "yes",
      rules: ["pii.logged", "secret.in-source", "transport.plain-http", "transport.tls-verify-off", "crypto.weak-password-hash", "sql.string-built", "pii.in-url", "supabase.rls-disabled", "supabase.policy-allows-all", "supabase.service-key-in-client", "supabase.function-no-auth", "secret.public-env", "mobile.token-in-plain-storage", "mobile.cleartext-traffic", "mobile.backup-allowed"],
      plain: "Protect personal data with security that fits the risk: encryption, access control, testing and the ability to recover.",
      evidence: "Security measures and when they were last tested." },
    { ref: "Art. 33–34", title: "Breach notification", inCode: "no",
      plain: "Tell the regulator within 72 hours of learning about a risky breach, and tell affected people when the risk to them is high.",
      evidence: "A breach procedure and a breach log." },
    { ref: "Art. 35", title: "Impact assessment (DPIA)", inCode: "no",
      plain: "Before risky processing, such as large-scale profiling or new AI uses on personal data, assess and reduce the risks.",
      evidence: "A completed DPIA." },
    { ref: "Art. 44–49", title: "Transfers outside the EU", inCode: "partly",
      plain: "Sending personal data outside the EU needs an approved route, such as an adequacy decision or standard contract clauses.",
      evidence: "The transfer tool used for each non-EU vendor." },
  ],
  watchOut: [
    "Pseudonymised data, like hashed emails, is still personal data. Only truly anonymous data is out of scope.",
    "An AI model trained on personal data may itself hold personal data. Don't assume it's anonymous.",
    "Analytics and session-replay tools often collect more than you think. Check what each SDK sends.",
    "Legitimate interests is not a free pass. It needs a written balancing test.",
  ],
  checkedOn: "2026-11-09",
};
