import { destructiveEnvOptIn } from "./guards.js";

export class CliGateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliGateError";
  }
}

export function requireDestructiveCliGate(options: {
  commandName: string;
  env?: NodeJS.ProcessEnv;
  confirm?: boolean;
  destructive?: boolean;
}): void {
  const env = options.env ?? process.env;
  if (!destructiveEnvOptIn(env)) {
    throw new CliGateError(
      `${options.commandName} is disabled. Set MISP_ALLOW_DESTRUCTIVE=true and pass --confirm --destructive to run destructive CLI commands.`,
    );
  }
  if (!options.confirm || !options.destructive) {
    throw new CliGateError(
      `${options.commandName} requires --confirm and --destructive for destructive CLI commands.`,
    );
  }
}

export function requireHardDeleteCliGate(options: {
  commandName: string;
  env?: NodeJS.ProcessEnv;
  confirm?: boolean;
  destructive?: boolean;
  confirmHard?: boolean;
}): void {
  requireDestructiveCliGate(options);
  if (!options.confirmHard) {
    throw new CliGateError(
      `${options.commandName} requires --confirm-hard for permanent hard deletes.`,
    );
  }
}
