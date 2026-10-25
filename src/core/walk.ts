import * as fsp from "node:fs/promises";
import * as path from "node:path";
import type { ScanIssue } from "../types";

export interface DirEntry {
  name: string;
  isDirectory(): boolean;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

/** Narrow filesystem surface so the walker can be tested without touching disk. */
export interface ScanFs {
  readdir(dir: string): Promise<DirEntry[]>;
  stat(target: string): Promise<{ size: number }>;
  readHead(target: string, maxBytes: number): Promise<{ content: string; truncated: boolean }>;
  realpath(target: string): Promise<string>;
}

export const nodeScanFs: ScanFs = {
  readdir: async dir => fsp.readdir(dir, { withFileTypes: true }),
  stat: async target => {
    const stats = await fsp.stat(target);
    return { size: stats.size };
  },
  readHead: async (target, maxBytes) => {
    const handle = await fsp.open(target, "r");
    try {
      const buffer = Buffer.alloc(maxBytes);
      const { bytesRead } = await handle.read(buffer, 0, maxBytes, 0);
      const stats = await handle.stat();
      return {
        content: buffer.subarray(0, bytesRead).toString("utf8"),
        truncated: stats.size > bytesRead
      };
    } finally {
      await handle.close();
    }
  },
  realpath: async target => fsp.realpath(target)
};

export type FileKind =
  | "dockerfile"
  | "compose"
  | "ini"
  | "composer-json"
  | "composer-lock"
  | "php"
  | "unknown";

const IGNORED_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  ".cache",
  ".idea",
  ".vscode",
  ".freebuff",
  "out",
  "out-test",
  "__pycache__"
]);

/** Directories that are ignored by default but can be opted into. */
const VENDOR_DIRS = new Set(["vendor"]);

export function classifyFile(filePath: string): FileKind {
  const base = path.basename(filePath).toLowerCase();
  if (base === "composer.json") return "composer-json";
  if (base === "composer.lock") return "composer-lock";
  if (/^dockerfile(\..+)?$/.test(base) || base.endsWith(".dockerfile")) return "dockerfile";
  if (/^(docker-)?compose(\..+)?\.ya?ml$/.test(base)) return "compose";
  if (base.endsWith(".php")) return "php";
  if (base === ".user.ini") return "ini";
  if (/^php\.ini([-.].+)?$/.test(base)) return "ini";
  if (base.endsWith(".ini") && /(^|[\\/])conf\.d([\\/]|$)/i.test(filePath)) return "ini";
  if (base.endsWith(".conf") && /(^|[\\/])pool\.d([\\/]|$)/i.test(filePath)) return "ini";
  if (base === "httpd.conf" || base === "apache2.conf") return "ini";
  if (base.endsWith(".conf") && /(apache|httpd)/i.test(filePath)) return "ini";
  return "unknown";
}

export interface WalkOptions {
  maxFiles: number;
  includeVendor: boolean;
}

export interface WalkResult {
  files: string[];
  truncated: boolean;
  issues: ScanIssue[];
}

function isIgnoredDirectory(name: string, options: WalkOptions): boolean {
  const lower = name.toLowerCase();
  if (VENDOR_DIRS.has(lower)) return !options.includeVendor;
  return IGNORED_DIRS.has(lower);
}

/**
 * Walk the workspace and return analysable files.
 *
 * Symlinked directories and files are skipped rather than followed, which keeps
 * the scan inside the workspace and avoids cycles; every skip is reported.
 */
export async function walkWorkspace(
  root: string,
  options: WalkOptions,
  scanFs: ScanFs
): Promise<WalkResult> {
  const files: string[] = [];
  const issues: ScanIssue[] = [];
  let truncated = false;
  let symlinksSkipped = 0;
  let unreadableDirs = 0;
  let realRoot = root;

  try {
    realRoot = await scanFs.realpath(root);
  } catch {
    realRoot = root;
  }

  const queue: string[] = [realRoot];
  while (queue.length > 0) {
    const dir = queue.shift() as string;
    let entries: DirEntry[];
    try {
      entries = await scanFs.readdir(dir);
    } catch {
      unreadableDirs += 1;
      continue;
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        symlinksSkipped += 1;
        continue;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith(".")) continue;
        if (isIgnoredDirectory(entry.name, options)) continue;
        queue.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (classifyFile(full) === "unknown") continue;
      if (files.length >= options.maxFiles) {
        // Only claim truncation when a matching file is genuinely skipped.
        truncated = true;
        continue;
      }
      files.push(full);
    }
    if (truncated && files.length >= options.maxFiles) {
      // Keep walking only far enough to know whether more matches exist.
      break;
    }
  }

  if (symlinksSkipped > 0) {
    issues.push({
      code: "SYMLINKS_SKIPPED",
      message: `${symlinksSkipped} symbolic link(s) were skipped; their contents were not analysed.`
    });
  }
  if (unreadableDirs > 0) {
    issues.push({
      code: "DIRS_UNREADABLE",
      message: `${unreadableDirs} directory/directories could not be read and were not analysed.`
    });
  }

  return { files, truncated, issues };
}
