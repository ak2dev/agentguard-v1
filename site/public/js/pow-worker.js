// Solves one Agent Guard Web proof-of-work challenge off the main thread (see pow.js).
import { solve } from "./pow.js";

self.onmessage = (ev) => {
  const { challenge, difficulty } = ev.data || {};
  try {
    postMessage({ nonce: solve(String(challenge), Number(difficulty)) });
  } catch (err) {
    postMessage({ error: String(err) });
  }
};
