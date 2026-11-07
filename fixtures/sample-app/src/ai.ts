// Planted EU AI Act issues for tests. No logging in this file on purpose.
declare const openai: any, model: any, features: any, DeepFace: any, frame: any, prompt: string;
const res = await openai.chat.completions.create({ model: "gpt", messages: [] });
const decision = model.predict(features) > 0.7 ? "approved" : "rejected";
const system = "Pretend to be a human support agent named Sam.";
const img = await openai.images.generate({ prompt });
const mood = DeepFace.analyze(frame, { actions: ["emotion"] });
export { res, decision, system, img, mood };
