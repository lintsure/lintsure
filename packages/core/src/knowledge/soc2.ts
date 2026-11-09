import type { FrameworkKnowledge } from "./types.js";

// Own-words summary of SOC 2 (AICPA Trust Services Criteria). The criteria text is licensed:
// we reference criterion IDs only and describe their intent in our own words.
export const soc2: FrameworkKnowledge = {
  id: "soc2",
  name: "SOC 2",
  kind: "attestation",
  summary:
    "SOC 2 is not a law. It's a report from an independent CPA firm saying your controls for security (and optionally availability, confidentiality, processing integrity and privacy) are designed well, and in a Type II, that they worked over a period of months. Business customers ask for it before they trust you with their data.",
  whoItAppliesTo:
    "Any company that stores or processes customer data and sells to businesses, mostly in the US but also worldwide.",
  applies(p) {
    if (p.b2bCustomers) return "Your business customers will likely ask for a SOC 2 report.";
    return null;
  },
  obligations: [
    { ref: "CC1", title: "Control environment", inCode: "no",
      plain: "Leadership sets the tone: ethics, clear roles, hiring and training.",
      evidence: "Org chart, code of conduct, background checks, training records." },
    { ref: "CC2", title: "Communication", inCode: "no",
      plain: "People inside and outside know their security duties and how to report problems.",
      evidence: "Policies shared with staff and a way for customers to report issues." },
    { ref: "CC3", title: "Risk assessment", inCode: "no",
      plain: "You regularly look for risks to your goals, including fraud and changes, and decide how to handle them.",
      evidence: "A yearly risk assessment." },
    { ref: "CC4", title: "Monitoring of controls", inCode: "no",
      plain: "You check that your controls keep working and fix gaps you find.",
      evidence: "Internal reviews and how gaps were tracked." },
    { ref: "CC5", title: "Control activities", inCode: "no",
      plain: "You turn policies into concrete controls, including controls over technology.",
      evidence: "Written policies mapped to controls." },
    { ref: "CC6.1", title: "Logical access", inCode: "yes", rules: ["secret.in-source", "pii.logged", "crypto.weak-password-hash", "session.cookie-insecure", "pii.in-url"],
      plain: "Only the right people and systems can reach data. Secrets are protected, passwords are stored safely.",
      evidence: "Access settings, secret storage and password hashing." },
    { ref: "CC6.2–6.3", title: "Granting and removing access", inCode: "no",
      plain: "Access is approved before it's given, reviewed regularly and removed quickly when people leave.",
      evidence: "Access requests and quarterly access reviews." },
    { ref: "CC6.6", title: "Boundary protection", inCode: "yes", rules: ["cors.any-origin"],
      plain: "Systems are protected from outside threats at their edges.",
      evidence: "Network and API access settings." },
    { ref: "CC6.7", title: "Data in transit", inCode: "yes", rules: ["transport.plain-http", "transport.tls-verify-off"],
      plain: "Data moving between systems is protected, usually with properly verified TLS.",
      evidence: "TLS settings and certificate checks." },
    { ref: "CC7.1", title: "Finding vulnerabilities", inCode: "yes", rules: ["sql.string-built"],
      plain: "You look for weaknesses and misconfigurations and fix them.",
      evidence: "Scan results and fix history." },
    { ref: "CC7.2–7.5", title: "Monitoring and incidents", inCode: "partly", rules: ["ai.call-not-logged"],
      plain: "You watch for unusual activity, respond to incidents and recover.",
      evidence: "Logs, alerts and an incident response plan." },
    { ref: "CC8.1", title: "Change management", inCode: "partly", rules: ["config.debug-on"],
      plain: "Changes are reviewed, tested and approved before they reach production.",
      evidence: "Pull request reviews and deploy records." },
    { ref: "CC9", title: "Vendor and business risk", inCode: "no",
      plain: "You manage risks from vendors and business disruption.",
      evidence: "Vendor list with reviews, and a continuity plan." },
    { ref: "P-series", title: "Privacy criteria (optional)", inCode: "partly", rules: ["pii.to-analytics"],
      plain: "If privacy is in scope: notice, choice, collection limits, use, retention, disclosure and quality of personal data.",
      evidence: "Privacy notice and data flow records." },
  ],
  watchOut: [
    "A SOC 2 report is about your controls, not a pass or fail certificate. Exceptions are normal and get described.",
    "Type I looks at one day. Type II covers a period, often 3 to 12 months, so start collecting evidence early.",
    "Using AI in your service can bring AI-specific risks into scope. Auditors may ask how you oversee it.",
    "The AICPA published a draft of updated criteria in October 2026. It is open for comment until 15 January 2027 and, if approved, would apply from engagements starting on or after 31 December 2027. The criterion numbers in Lintsure follow the current criteria. Check which version your auditor uses.",
  ],
  checkedOn: "2026-11-09",
};
