
import { Context, Next } from "hono";
import { getSignedCookie, setSignedCookie } from 'hono/cookie';
import { buf2str } from "../util";

export interface SessionConfig {
  /**
   * The session cookie name.
   */
  cookie: string,
  /**
   * The key to set on the request/context object.
   * Default is 'sessionId'.
   */
  reqKey: string,
  /**
   * Get the secret from the hono Context.
   * Default returns `c.env.COOKIE_SECRET`.
   */
  secret: (c: Context) => string,
}

export const SESSION_DEFAULT: SessionConfig = {
  cookie: 'SESSIONID',
  reqKey: 'sessionId',
  secret: (c) => c.env.COOKIE_SECRET,
}

export function sessionMiddleware(config: SessionConfig): (c: Context, next: Next) => Promise<void> {
  return async (c, next) => {
    const secret = config.secret(c);
    let sessId = await getSignedCookie(c, secret, config.cookie);
    if (!sessId) {
      sessId = btoa(buf2str(crypto.getRandomValues(new Uint8Array(20))));
      const expires = new Date();
      expires.setDate(expires.getDate() + 2);
      const domain = new URL(c.req.url).host;
      await setSignedCookie(c, config.cookie, sessId, secret, {
        // domain,
        expires,
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      });
    }
    c.set(config.reqKey, sessId);
    await next();
  };
}
