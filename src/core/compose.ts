import type { ImageReference } from "./dockerfile";
import { parseImageReference } from "./dockerfile";

export interface ComposeParseResult {
  images: ImageReference[];
  /** Lines that looked like an image reference but could not be resolved. */
  notes: string[];
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function stripComment(value: string): string {
  // YAML comments start with " #"; a "#" without preceding whitespace is part of
  // the scalar (for example in a digest). This is a deliberately conservative rule.
  const match = /\s#/.exec(value);
  return (match ? value.slice(0, match.index) : value).trim();
}

/**
 * Scan a Compose file for `image:` values.
 *
 * This is a line scanner, not a YAML parser: it does not evaluate anchors,
 * merges or multi-line scalars. Anything it cannot read is reported instead of
 * being treated as safe.
 */
export function parseCompose(content: string): ComposeParseResult {
  const images: ImageReference[] = [];
  const notes: string[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((line, index) => {
    const match = /^\s*(?:-\s*)?image\s*:\s*(.*?)\s*$/.exec(line);
    if (!match) return;
    const value = unquote(stripComment(match[1]));
    if (value.length === 0) {
      notes.push(`Line ${index + 1}: image key has no value.`);
      return;
    }
    const parsed = parseImageReference(value, index + 1);
    if (!parsed) return;
    images.push(parsed);
  });

  return { images, notes };
}
