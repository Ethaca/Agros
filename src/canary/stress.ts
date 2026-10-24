import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { attacks, seededRandom } from "./attacks.js";
import { positive } from "./issue.js";
import { scan } from "./scan.js";
import { bind, loadRegistry, CanaryError, sha256 } from "./registry.js";
import { StressResult } from "./types.js";

export function stress(registryPath: string, trials = 20, seed = 7): StressResult {
  positive(trials, "trials");
  if (!Number.isSafeInteger(seed)) throw new CanaryError("seed must be an integer");
  const { registry, registrySha256 } = loadRegistry(registryPath);
  const names = Object.keys(registry.recipients);
  if (names.length < 2) throw new CanaryError("stress requires at least two recipients");
  const recipient = names[1]!, otherRecipient = names[0]!;
  const load = (name: string): string => {
    const info = registry.recipients[name]!;
    const bytes = readFileSync(join(dirname(registryPath), info.copy));
    if (sha256(bytes) !== info.sha256) throw new CanaryError("copy hash mismatch");
    return bytes.toString("utf8");
  };
  const result: StressResult = { ...bind(registry, registrySha256), seed, trials, attacks: [] };
  for (const [index, attack] of attacks(load(recipient), load(otherRecipient), registry, recipient, otherRecipient).entries()) {
    let identified = 0, mixed = 0, unidentified = 0, misattributed = 0;
    for (let t = 0; t < trials; t++) {
      const result = scan(attack.apply(seededRandom(seed + index * 100_003 + t)), registry, registrySha256);
      if (result.verdict === "UNIDENTIFIED") unidentified++;
      else if (result.verdict === "MIXED_SOURCES") mixed++;
      else if (result.recipients[0]?.recipient === recipient) identified++;
      else misattributed++;
    }
    const rate = (attack.mixed ? mixed : identified) / trials;
    result.attacks.push({ id: attack.id, expected: attack.expected, executed: true, trials, identified, mixed, unidentified, misattributed, rate, standardError: Math.sqrt(rate * (1 - rate) / trials) });
  }
  for (const id of ["S6", "S8"]) result.attacks.push({ id, expected: "unmeasured", executed: false, trials: 0, identified: 0, mixed: 0, unidentified: 0, misattributed: 0, rate: null, standardError: null });
  return StressResult.parse(result);
}
