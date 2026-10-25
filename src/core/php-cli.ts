import { isSpawnFailure, type ProcessRunner } from "./process";
import { parseVersion, type ParsedVersion } from "./version";

export type PhpCliStatus = "ok" | "not-found" | "failed" | "unparsed";

export interface PhpCliProbe {
  status: PhpCliStatus;
  executable: string;
  version?: ParsedVersion;
  sapi?: string;
  raw?: string;
  message?: string;
}

export interface PhpCliOptions {
  /** Configured php executable; defaults to "php" from PATH. */
  executable?: string;
  timeoutMs: number;
}

/**
 * Ask PHP for its version. Only `-v` is ever passed: the scanner never executes
 * workspace files.
 */
export async function probePhpCli(
  options: PhpCliOptions,
  runner: ProcessRunner
): Promise<PhpCliProbe> {
  const executable = options.executable?.trim() || "php";
  let result;
  try {
    result = await runner.run(executable, ["-v"], { timeoutMs: options.timeoutMs });
  } catch (error) {
    if (isSpawnFailure(error)) {
      if (error.code === "ENOENT") {
        return { status: "not-found", executable, message: "The php executable was not found." };
      }
      return {
        status: "failed",
        executable,
        message: `The php executable could not be started (${error.code}).`
      };
    }
    return {
      status: "failed",
      executable,
      message: `Unexpected error while running php: ${error instanceof Error ? error.message : String(error)}.`
    };
  }

  const combined = `${result.stdout}\n${result.stderr}`.trim();
  if (result.timedOut) {
    return {
      status: "failed",
      executable,
      message: `php -v timed out after ${options.timeoutMs} ms.`,
      raw: combined.slice(0, 300)
    };
  }

  const match = /PHP\s+([0-9][^\s(]*)\s*\(([^)]*)\)/.exec(combined);
  if (!match) {
    return {
      status: "unparsed",
      executable,
      message: "php ran but its output did not contain a recognisable version.",
      raw: combined.slice(0, 300)
    };
  }

  const version = parseVersion(match[1]);
  if (!version) {
    return {
      status: "unparsed",
      executable,
      message: `php reported version "${match[1]}", which could not be parsed.`,
      raw: combined.slice(0, 300)
    };
  }

  return {
    status: "ok",
    executable,
    version,
    sapi: match[2].trim(),
    raw: match[0]
  };
}
