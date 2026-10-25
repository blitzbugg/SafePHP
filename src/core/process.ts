import { execFile } from "node:child_process";

export interface RunOptions {
  cwd?: string;
  timeoutMs: number;
  maxBuffer?: number;
}

export interface RunResult {
  stdout: string;
  stderr: string;
  /** Process exit code, or -1 when the process was killed or did not report one. */
  code: number;
  timedOut: boolean;
}

/** A spawn failure (missing executable, refused script) as opposed to an exit code. */
export interface SpawnFailure {
  code: string;
  message: string;
}

export interface ProcessRunner {
  run(command: string, args: string[], options: RunOptions): Promise<RunResult>;
}

export const DEFAULT_MAX_BUFFER = 10 * 1024 * 1024;

/**
 * Run an executable with a fixed argument vector.
 *
 * `shell` is always false, so no argument is interpreted by a shell. Spawn
 * failures are rejected; non-zero exit codes are resolved so callers can inspect
 * stdout (Composer signals findings with a non-zero status).
 */
export const nodeProcessRunner: ProcessRunner = {
  run(command, args, options) {
    return new Promise<RunResult>((resolve, reject) => {
      execFile(
        command,
        args,
        {
          cwd: options.cwd,
          timeout: options.timeoutMs,
          maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
          windowsHide: true,
          shell: false,
          encoding: "utf8"
        },
        (error, stdout, stderr) => {
          if (error === null) {
            resolve({ stdout: stdout ?? "", stderr: stderr ?? "", code: 0, timedOut: false });
            return;
          }
          const err = error as NodeJS.ErrnoException & {
            code?: number | string;
            killed?: boolean;
            signal?: string;
          };
          if (typeof err.code === "string") {
            reject({ code: err.code, message: err.message } satisfies SpawnFailure);
            return;
          }
          const timedOut = err.killed === true;
          resolve({
            stdout: stdout ?? "",
            stderr: stderr ?? "",
            code: typeof err.code === "number" ? err.code : -1,
            timedOut
          });
        }
      );
    });
  }
};

export function isSpawnFailure(value: unknown): value is SpawnFailure {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as SpawnFailure).code === "string" &&
    typeof (value as SpawnFailure).message === "string"
  );
}
