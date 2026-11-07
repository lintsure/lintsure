import type { FrameworkKnowledge } from "./types.js";

// Own-words summary of Regulation (EU) 2024/1689 as amended by the Digital Omnibus on AI,
// Regulation (EU) 2026/1744 (in force July 2026). Not legal advice.
const HIGH_RISK_AREAS = new Set(["credit", "employment", "education", "essential-services", "insurance", "biometrics", "law-enforcement", "migration", "justice", "critical-infrastructure"]);

export const euAiAct: FrameworkKnowledge = {
  id: "eu-ai-act",
  name: "EU AI Act",
  kind: "law",
  summary:
    "The EU's law on AI sorts AI uses by how much harm they could do. A few uses are banned. Uses that affect people's lives, like credit, hiring or education, are high-risk and need human oversight, logs, documentation and risk management. Chatbots and AI-made media need to be open about being AI. Most other AI only needs staff to understand the tools they use.",
  whoItAppliesTo:
    "Anyone who builds an AI system and offers it in the EU (a provider), and anyone who uses one in their work in the EU (a deployer), even if the company is based elsewhere.",
  applies(p) {
    if (!p.usesAI) return null;
    if (!p.euUsers) return null;
    if (p.decisionArea && HIGH_RISK_AREAS.has(p.decisionArea)) return `Your AI helps decide about people in a high-risk area (${p.decisionArea}), so the strictest rules apply.`;
    if (p.generativeAI || p.interactsWithPeople) return "Your AI talks to people or makes content, so the openness rules apply.";
    return "You use AI and have users in the EU. Light duties apply, mainly AI literacy for your team.";
  },
  timeline: [
    { date: "2025-02-02", what: "Banned practices and the AI literacy duty start to apply." },
    { date: "2025-08-02", what: "Rules for general-purpose AI model providers start to apply." },
    { date: "2026-08-02", what: "General date of application, including most openness duties for chatbots and AI content." },
    { date: "2026-12-02", what: "New bans on AI that makes non-consensual intimate images or child abuse material. Deadline for older generative systems to mark their output as AI-made." },
    { date: "2027-12-02", what: "High-risk rules apply to uses listed in Annex III (credit, hiring, education and others). Moved later by the 2026 Digital Omnibus." },
    { date: "2028-08-02", what: "High-risk rules apply to AI that is a safety part of products covered by Annex I (machinery, medical devices and others)." },
  ],
  obligations: [
    { ref: "Art. 4", title: "AI literacy", inCode: "no",
      plain: "Take steps so the people who build and use your AI understand it well enough for their role. Softened in 2026 from a strict duty to a duty to support.",
      evidence: "A short training plan and who has done it." },
    { ref: "Art. 5", title: "Banned practices", inCode: "partly", rules: ["ai.emotion-or-biometric"],
      plain: "Some uses are not allowed at all, for example manipulating people in harmful ways, social scoring, reading emotions at work or school, and (from December 2026) making intimate images of real people without consent.",
      evidence: "A written check that none of your features fall into a banned use." },
    { ref: "Art. 6 + Annex III", title: "Is it high-risk?", inCode: "partly", rules: ["ai.automated-decision"],
      plain: "AI used for things like credit, hiring, education, essential services or biometrics is high-risk unless it only does a narrow, preparatory task and doesn't really shape the outcome.",
      evidence: "Your reasoning for the risk tier, written down." },
    { ref: "Art. 9", title: "Risk management", inCode: "no",
      plain: "High-risk systems need a running process to find, test and reduce risks across the system's life.",
      evidence: "A risk register for the AI system, reviewed over time." },
    { ref: "Art. 10", title: "Data and data governance", inCode: "partly",
      plain: "Training and test data must fit the purpose, be checked for bias and gaps, and be handled with care.",
      evidence: "A note on where the data came from and how it was checked." },
    { ref: "Art. 11", title: "Technical documentation", inCode: "no",
      plain: "Keep a description of how the system works, what it's for, its limits and how it was tested.",
      evidence: "Technical documentation following Annex IV." },
    { ref: "Art. 12", title: "Record-keeping (logs)", inCode: "yes", rules: ["ai.call-not-logged"],
      plain: "The system should automatically log what it did, so events can be traced later.",
      evidence: "Sample logs showing time, model version, input reference and output." },
    { ref: "Art. 13", title: "Instructions for use", inCode: "no",
      plain: "Give the people who deploy your system clear instructions: what it does, how well, its limits and how to oversee it.",
      evidence: "Instructions for deployers." },
    { ref: "Art. 14", title: "Human oversight", inCode: "partly", rules: ["ai.automated-decision"],
      plain: "A person must be able to understand the output, ignore it, override it or stop the system.",
      evidence: "The review or override step, and who uses it." },
    { ref: "Art. 15", title: "Accuracy, robustness, security", inCode: "partly", rules: ["secret.in-source", "sql.string-built"],
      plain: "The system should perform as stated, cope with errors and resist attacks such as data poisoning or prompt injection.",
      evidence: "Test results and the security measures in place." },
    { ref: "Art. 17", title: "Quality management system", inCode: "no",
      plain: "High-risk providers need a written quality system covering design, testing, changes and incidents. Smaller firms can keep it simpler.",
      evidence: "The quality manual and its procedures." },
    { ref: "Art. 26", title: "Duties when you use high-risk AI", inCode: "no",
      plain: "If you use someone else's high-risk AI, follow its instructions, assign human oversight, watch how it works and keep its logs.",
      evidence: "Named overseers and kept logs." },
    { ref: "Art. 50(1)", title: "Tell people they're talking to AI", inCode: "yes", rules: ["ai.hides-being-ai"],
      plain: "If your AI talks with people, they must know it's an AI unless that's obvious.",
      evidence: "The notice shown to users." },
    { ref: "Art. 50(2)", title: "Mark AI-made content", inCode: "partly", rules: ["ai.synthetic-media"],
      plain: "AI-generated images, audio, video and text should carry a machine-readable mark that they're AI-made.",
      evidence: "How output is marked, for example C2PA metadata or watermarks." },
    { ref: "Art. 50(4)", title: "Label deepfakes", inCode: "partly", rules: ["ai.synthetic-media"],
      plain: "If you publish realistic fake media of people, places or events, say that it's AI-made.",
      evidence: "The label shown to viewers." },
  ],
  watchOut: [
    "The risk tier depends on the use, not the model. The same model can be low-risk in one feature and high-risk in another.",
    "Using a vendor's AI doesn't remove your duties. As a deployer you still have some.",
    "The 2026 Digital Omnibus moved high-risk dates later, but bans and openness duties still apply on their original or earlier dates.",
    "Code can show signals of risk. Only a person can decide the legal tier.",
  ],
  checkedOn: "2026-11-07",
};
