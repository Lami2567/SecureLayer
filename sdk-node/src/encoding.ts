import { Buffer } from "node:buffer";

export type DataLike = string | Uint8Array | ArrayBuffer | object;

export function toBuffer(input: DataLike): Buffer {
  if (typeof input === "string") {
    return Buffer.from(input, "utf8");
  }

  if (input instanceof ArrayBuffer) {
    return Buffer.from(input);
  }

  if (ArrayBuffer.isView(input)) {
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  }

  return Buffer.from(stableJson(input), "utf8");
}

export function fromBase64(value: string | Uint8Array): Buffer {
  return typeof value === "string" ? Buffer.from(value, "base64") : Buffer.from(value);
}

export function stableJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }

  if (value && typeof value === "object" && !(value instanceof Uint8Array) && !(value instanceof ArrayBuffer)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, sortJson(entry)]),
    );
  }

  return value;
}
