// encode to utf8 I guess
const ENCODER = new TextEncoder();
// decode with a charset that doesn't actually convert any bytes
const DECODER = new TextDecoder('iso-8859-1');

/** Convert a `Date` into a unix epoch timestamp. */
export function date2unix(d: Date): number {
  return Math.floor(d.getTime() / 1000);
}

/** Convert a unix epoch timestamp (in seconds) to a JS `Date`. */
export function unix2date(ux: number): Date {
  return new Date(ux * 1000);
}

/**
 * Convert a `string` to a `Uint8Array`.
 */
export function str2buf(s: string): Uint8Array {
  return ENCODER.encode(s);
}

/**
 * Convert a buffer to a string. Buffer does NOT have to be utf-8.
 */
export function buf2str(buf: Uint8Array): string {
  return DECODER.decode(buf);
}

export type Result<T, E> = { ok: true, value: T }|{ ok?: false, error: E };
