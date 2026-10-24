export class RunnerError extends Error {
  constructor(message: string, readonly logTail: string[] = []) {
    super(logTail.length ? `${message}\n--- last ${logTail.length} log lines ---\n${logTail.join("\n")}` : message);
  }
}
