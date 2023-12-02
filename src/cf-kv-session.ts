import { ISession } from ".";

export type KeyTransform = (key: string) => string;

/**
 * Implementation of the {@link ISession} using a cloudflare KV namespace.
 * 
 * While KV isn't the ideal storage for this, writes to a given value are
 * instant in the datacenter where they occur, and take up to 60 seconds to propogate.
 * Since most connections will be to the same datacenter, this is fine.
 */
export class KVSessionStorage implements ISession {
  /**
   * Construct a KVSessionStorage.
   * @param kv KV namespace
   * @param transform key transformer (e.g. to add a session key)
   */
  constructor(
    public kv: KVNamespace,
    public transform: KeyTransform = (s) => s,
  ) {}

  put<T>(key: string, value: T, expires?: number): Promise<void> {
    const kvkey = this.transform(key);
    return this.kv.put(kvkey, JSON.stringify(value), { expiration: expires });
  }
  get<T>(key: string): Promise<T | null> {
    const kvkey = this.transform(key);
    return this.kv.get(kvkey, 'json');
  }
  delete(key: string): Promise<void> {
    const kvkey = this.transform(key);
    return this.kv.delete(kvkey);
  }
}
