import type { ObservationResolution } from "../types";
import { parseVersion, type ParsedVersion } from "./version";

export interface ImageReference {
  /** Repository name without registry, tag or digest. Only "php" images are returned. */
  name: string;
  tag?: string;
  digest?: string;
  stage?: string;
  variant?: string;
  resolution: ObservationResolution;
  version?: ParsedVersion;
  raw: string;
  line: number;
  /** Populated when the reference could not be resolved (digest-only, ARG, latest, ...). */
  reason?: string;
}

export interface ImageParseIssue {
  line: number;
  message: string;
}

/**
 * Parse a PHP container image reference.
 *
 * Returns undefined for images that are not PHP, so the caller can ignore them
 * without treating them as "no finding".
 */
export function parseImageReference(text: string, line: number): ImageReference | undefined {
  const raw = text.trim();
  if (raw.length === 0) return undefined;

  const withoutDigest = raw.split("@");
  const digest = withoutDigest.length > 1 ? withoutDigest.slice(1).join("@") : undefined;
  const nameAndTag = withoutDigest[0];

  const lastSlash = nameAndTag.lastIndexOf("/");
  const lastColon = nameAndTag.lastIndexOf(":");
  const hasTag = lastColon > lastSlash;
  const name = hasTag ? nameAndTag.slice(0, lastColon) : nameAndTag;
  const tag = hasTag ? nameAndTag.slice(lastColon + 1) : undefined;

  const lastSegment = name.split("/").pop() ?? name;
  if (lastSegment.toLowerCase() !== "php") return undefined;

  const base: ImageReference = {
    name,
    raw,
    line,
    resolution: "unresolved",
    ...(tag !== undefined ? { tag } : {}),
    ...(digest !== undefined ? { digest } : {})
  };

  if (tag === undefined) {
    return {
      ...base,
      reason: digest
        ? "The reference pins a digest only, so the PHP version cannot be read from the text."
        : "No tag is given, so the image implicitly uses the latest tag."
    };
  }

  if (/\$\{?[A-Za-z_]/.test(tag)) {
    return { ...base, reason: `The tag "${tag}" is interpolated and could not be resolved statically.` };
  }

  if (tag.toLowerCase() === "latest") {
    return { ...base, reason: "The image uses the latest tag, which is not a fixed PHP version." };
  }

  const numeric = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(tag);
  if (!numeric) {
    return { ...base, reason: `The tag "${tag}" does not start with a PHP version.` };
  }

  const rest = tag.slice(numeric[0].length);
  if (numeric[2] === undefined) {
    if (rest.length > 0 && !rest.startsWith("-")) {
      return { ...base, reason: `The tag "${tag}" is not a PHP version this scanner can interpret.` };
    }
    return {
      ...base,
      resolution: "major-floating",
      reason: `The tag "${tag}" pins only a major version, so the branch and patch level are unknown.`
    };
  }

  const version = parseVersion(tag);
  if (!version) {
    return { ...base, reason: `The tag "${tag}" is not a PHP version this scanner can interpret.` };
  }

  const variant = version.vendorSuffix ? version.vendorSuffix.replace(/^-/, "") : undefined;
  const withVersion: ImageReference = {
    ...base,
    version,
    ...(variant !== undefined ? { variant } : {})
  };

  if (numeric[3] === undefined) {
    return {
      ...withVersion,
      resolution: "branch-floating",
      reason: `The tag "${tag}" floats within the ${numeric[1]}.${numeric[2]} branch and does not identify a patch level.`
    };
  }

  return { ...withVersion, resolution: "exact" };
}

export interface DockerfileParseResult {
  images: ImageReference[];
  issues: ImageParseIssue[];
}

interface Expansion {
  value: string;
  missing: string[];
}

function expandVariables(text: string, args: Map<string, string>): Expansion {
  const missing: string[] = [];
  const value = text.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (match, braced: string | undefined, fallback: string | undefined, bare: string | undefined) => {
      const name = braced ?? bare ?? "";
      const known = args.get(name);
      if (known !== undefined) return known;
      if (fallback !== undefined) return fallback;
      missing.push(name);
      return match;
    }
  );
  return { value, missing };
}

/** Parse FROM instructions in a Dockerfile, honouring simple ARG substitution. */
export function parseDockerfile(content: string): DockerfileParseResult {
  const images: ImageReference[] = [];
  const issues: ImageParseIssue[] = [];
  const args = new Map<string, string>();

  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) return;

    const argMatch = /^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$/i.exec(trimmed);
    if (argMatch) {
      const name = argMatch[1];
      const value = argMatch[2];
      if (value !== undefined) args.set(name, value.trim().replace(/^["']|["']$/g, ""));
      return;
    }

    const fromMatch = /^FROM\s+(.+)$/i.exec(trimmed);
    if (!fromMatch) return;

    const tokens = fromMatch[1].trim().split(/\s+/);
    let index2 = 0;
    while (index2 < tokens.length && tokens[index2].startsWith("--")) index2 += 1;
    const referenceToken = tokens[index2];
    if (!referenceToken) {
      issues.push({ line: lineNumber, message: "FROM instruction has no image reference." });
      return;
    }

    const stageToken = tokens[index2 + 1];
    const stage = stageToken && stageToken.toLowerCase() === "as" ? tokens[index2 + 2] : undefined;

    const expanded = expandVariables(referenceToken, args);
    if (expanded.missing.length > 0) {
      const unresolvedToken = expanded.value;
      const phpLike = /(^|[/:])php([:/]|$)/i.test(unresolvedToken);
      if (phpLike) {
        images.push({
          name: "php",
          raw: referenceToken,
          line: lineNumber,
          resolution: "unresolved",
          reason: `The image reference depends on build argument(s) ${expanded.missing.map(n => `"${n}"`).join(", ")} that could not be resolved statically.`,
          ...(stage !== undefined ? { stage } : {})
        });
      }
      return;
    }

    const parsed = parseImageReference(expanded.value, lineNumber);
    if (!parsed) return;
    images.push({ ...parsed, raw: referenceToken, ...(stage !== undefined ? { stage } : {}) });
  });

  return { images, issues };
}
