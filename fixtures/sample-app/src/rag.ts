// Planted: retrieved pages go straight into the system prompt.
declare const chunks: string[];
export const system = `Answer from these pages: ${chunks.join("\n")}`;
