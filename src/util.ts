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

/**
 * Returns `true` iff `outer` contains every element of `inner`.
 * @param outer array which must contain all of `inner`
 * @param inner strict subset of `outer`
 */
export function hasAll<T>(outer: T[], inner: Iterable<T>): boolean {
  for (const e of inner) {
    if (!outer.includes(e)) {
      return false;
    }
  }
  return true;
}

/**
 * Sets the key on the given request object. If the request object has
 * a `set` method (e.g. hono `Context`), that will be called instead.
 * 
 * @param req The {@link Request} object, a hono `Context`, or some other
 *            object which will be carried through the handling chain.
 * @param key The key to set
 * @param value the value for the key
 */
export function requestSet(req: Record<string,any>, key: string, value: any) {
  if (typeof req.set === 'function') {
    req.set(key, value);
  } else {
    req[key] = value;
  }
}

export type Result<T, E> = { ok: true, value: T }|{ ok?: false, error: E };
