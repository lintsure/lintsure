import type { FrameworkKnowledge } from "./types.js";

// Own-words summary of ISO/IEC 27001:2022 (with Amendment 1:2024). The standard is licensed:
// we reference clause and Annex A control numbers only and describe intent in our own words.
export const iso27001: FrameworkKnowledge = {
  id: "iso-27001",
  name: "ISO/IEC 27001",
  kind: "standard",
  summary:
    "An international standard for running an information security management system: a repeatable way to find security risks, pick controls, and keep improving. You get certified by an accredited body after an audit. Annex A lists 93 controls in four groups: organizational, people, physical and technological. You choose which apply and explain why.",
  whoItAppliesTo:
    "Any organization that wants to prove to customers, often in Europe and Asia, that it manages information security in a structured way.",
  applies(p) {
    if (p.wantsCertification) return "Customers or partners ask for an ISO 27001 certificate.";
    if (p.b2bCustomers && !p.usMarket) return "Business customers outside the US often expect ISO 27001.";
    return null;
  },
  obligations: [
    { ref: "Clauses 4–10", title: "The management system", inCode: "no",
      plain: "Define scope, get leadership commitment, assess and treat risks, set objectives, run internal audits and management reviews, and fix nonconformities. Amendment 1 adds that you consider climate change in your context.",
      evidence: "Scope, risk assessment, Statement of Applicability, internal audit and management review records." },
    { ref: "A.5", title: "Organizational controls (37)", inCode: "no",
      plain: "Policies, roles, asset inventory, supplier security, incident handling, legal duties and privacy.",
      evidence: "Policies, supplier agreements and incident records." },
    { ref: "A.5.34", title: "Privacy and protection of personal data", inCode: "partly", rules: ["pii.to-analytics"],
      plain: "Meet the privacy laws and contracts that apply to personal data you hold.",
      evidence: "Privacy compliance records." },
    { ref: "A.6", title: "People controls (8)", inCode: "no",
      plain: "Screening, terms of employment, awareness training, discipline and remote work.",
      evidence: "Training and screening records." },
    { ref: "A.7", title: "Physical controls (14)", inCode: "no",
      plain: "Protect offices, equipment and media. Often inherited from your cloud provider.",
      evidence: "Cloud provider reports and office measures." },
    { ref: "A.8.5", title: "Secure authentication", inCode: "yes", rules: ["session.cookie-insecure"],
      plain: "Log-in and sessions are built so they can't easily be stolen or bypassed.",
      evidence: "Authentication and session settings." },
    { ref: "A.8.9", title: "Configuration management", inCode: "yes", rules: ["config.debug-on"],
      plain: "Systems are set up securely and settings are controlled.",
      evidence: "Baseline configurations." },
    { ref: "A.8.11", title: "Data masking", inCode: "yes", rules: ["pii.logged", "pii.in-url"],
      plain: "Hide or reduce sensitive data where full values aren't needed, such as in logs.",
      evidence: "Masking in logs and test data." },
    { ref: "A.8.15–8.16", title: "Logging and monitoring", inCode: "partly", rules: ["ai.call-not-logged"],
      plain: "Record important events, protect the logs and watch them for problems.",
      evidence: "Log setup and alert rules." },
    { ref: "A.8.20", title: "Network security", inCode: "yes", rules: ["transport.plain-http", "transport.tls-verify-off", "cors.any-origin"],
      plain: "Networks and connections are protected and controlled.",
      evidence: "Network and TLS settings." },
    { ref: "A.8.24", title: "Use of cryptography", inCode: "yes", rules: ["secret.in-source", "crypto.weak-password-hash"],
      plain: "Use strong cryptography correctly and manage keys safely, not in source code.",
      evidence: "Crypto and key management rules." },
    { ref: "A.8.25–8.29", title: "Secure development", inCode: "yes", rules: ["sql.string-built"],
      plain: "Build software securely: secure design, coding, testing and separation of environments.",
      evidence: "Secure coding guidelines and test results." },
    { ref: "A.8.32", title: "Change management", inCode: "partly",
      plain: "Changes to systems are controlled and reviewed.",
      evidence: "Change records." },
  ],
  watchOut: [
    "Certification is for the management system, not the product. Code findings feed into it but don't replace it.",
    "Your Statement of Applicability must explain every Annex A control you include or exclude.",
    "Certificates to the 2013 version expired in October 2025. Use the 2022 version.",
  ],
  checkedOn: "2026-11-07",
};
