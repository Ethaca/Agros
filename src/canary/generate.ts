import { derive } from "./token.js";
import { Row } from "./types.js";

export function template(key: Buffer, dataset: string, recipient: string, i: number, id: string, value: string): Row {
  const n = derive(key, "stem", dataset, recipient, i).readUInt32BE(0);
  const amount = 10 + n % 80;
  const subjects = ["warehouse", "laboratory", "repair center", "distribution hub"];
  const question = `At the ${subjects[n % subjects.length]}, shipment ${n.toString(36)} of model ${value} contains ${amount} units. If 3 units are reserved, how many remain available?`;
  return Row.parse({ id, question, choices: [String(amount - 3), String(amount), String(amount + 3)], answer: String(amount - 3) });
}
