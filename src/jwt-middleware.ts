import { serialize, parse, CookieSerializeOptions } from "cookie";
import jwt, { JwtPayload } from '@tsndr/cloudflare-worker-jwt';
import { Result, date2unix, unix2date } from "./util";

const BEARER = 'Bearer ';

export type CookieOptions = CookieSerializeOptions;

export interface JwtAuthParams<T, C = any> {
  /** Key to use for the JWT cookie. */
  cookie: string,
  /** How long the JWT is valid for, in seconds. Default is 15 days. */
  tokenTTL?: number,
  /** If true, also check bearer tokens when looking for a JWT */
  allowBearer?: boolean,
  /** cookie serialization options */
  cookieOptions?: CookieOptions,
  /**
   * Function which will take a context object and return the secret used to sign JWTs.
   * 
   * Environments like Cloudflare Workers don't have access to secrets until
   * the actual handler is called, thus the use of a callback here.
   */
  secret: (ctx: C) => string,
  /**
   * Implements a user-defined check of the JWT before it's considered valid.
   * 
   * One common use-case is to validate the `iat` field against a 'logout everywhere'
   * timestamp, allowing users to force a logout in case of an account breach.
   */
  isValid?: (ctx: C, payload: JwtPayload<T>) => boolean|Promise<boolean>,
}

export class JwtManager<T, C = any> {
  private readonly params: JwtAuthParams<T, C> & {
    tokenTTL: number,
  };

  /**
   * Context value passed to callbacks.
   * 
   * Use {@link withContext} to create a new `JwtManager` with a different context value.
   */
  public readonly ctx?: C;

  constructor(params: JwtAuthParams<T,C>, ctx?: C) {
    if (params instanceof JwtManager) {
      // If we have the copy constructor, we don't need to set any
      // defaults, we can just use the params reference directly.
      this.params = params.params;
    } else {
      // By listing each key specifically, we ensure our internal
      // data doesn't have extra keys, and can add defaults.
      this.params = {
        cookie: params.cookie,
        cookieOptions: params.cookieOptions ?? {
          path: '/',
          sameSite: 'lax',
          httpOnly: true,
          secure: true,
        },
        secret: params.secret,
        isValid: params.isValid || ((a,b) => true),
        tokenTTL: params.tokenTTL || (60 * 60 * 24 * 15),
      };
    }
    // Assign context
    this.ctx = ctx;
  }

  /** @see {@link JwtAuthParams.cookie} */
  public get cookie(): string { return this.params.cookie; }

  /** @see {@link JwtAuthParams.tokenTTL} */
  public get tokenTTL(): number { return this.params.tokenTTL; }

  public withContext(ctx: C): JwtManager<T, C> {
    return new JwtManager(this as any, ctx);
  }

  /**
   * Redirect 
   * @param req the incoming request
   * @param token the JWT string, which will be decoded to get the expiration time
   * @param destUrl the url to redirect to after the cookie is set
   * @returns 
   */
  public async setCookie(req: Request, token: string, destUrl: string): Promise<Response> {
    // don't use req, but have it for future in case we need it
    let _ = req;
    // we do NOT verify this token, we just decode it for the exp time
    const { payload } = jwt.decode(token);
    const expires = payload?.exp ? unix2date(payload?.exp) : undefined;
    const setCookie = serialize(this.cookie, token, {
      ...this.params.cookieOptions!!,
      expires,
    });
    const headers = {
      'Set-Cookie': setCookie,
      'Location': destUrl,
    };
    return new Response('', { status: 303, headers });
  }

  /**
   * Returns a 'set-cookie' header value which will clear the authentication cookie.
   * Note that browsers and malicious actors may persist the cookie even after you expect it to be cleared.
   * 
   * @returns a 'set-cookie' header value that will clear the cookie
   */
  public clearCookie(): string {
    return serialize(this.cookie, '', {
      ...this.params.cookieOptions!!,
      expires: new Date(0),
    });
  }

  /**
   * Calls {@link findJwt} to get the JWT token from the request,
   * then {@link decodeJwt} to verify and safely decode it. If any
   * of those steps fails for any reason, returns `null`.
   * 
   * @param req the request to get the token from
   * @returns the parsed JWT, or null if validation failed
   */
  public async safeGetToken(req: Request): Promise<T|null> {
    const token = this.findJwt(req);
    if (!token) {
      return null;
    }
    const out = await this.decodeJwt(token);
    if (out.ok) {
      return out.value;
    } else {
      return null;
    }
  }

  /**
   * Searches cookies and headers for the authorization token.
   * 
   * First the cookie named in `params` is checked.
   * If not found, and `allowBearer` is `true`, then the `Authorization` header
   * is checked for a `Bearer` token. 
   * 
   * @param req the Request
   * @returns the JWT token or null if not found
   */
  public findJwt(req: Request): string|null {
    const cookies = parse(req.headers.get('cookie') || '');
    const token = cookies[this.cookie];
    if (token) {
      return token;
    }
    const authHdr = req.headers.get('authorization');
    if (this.params.allowBearer && authHdr && authHdr.startsWith(BEARER)) {
      return authHdr.substring(BEARER.length);
    }
    return null;
  }

  public createJwt(data: T): Promise<string> {
    // expires after 15 days
    const exp = date2unix(new Date()) + this.tokenTTL;
    const payload = { ...data, exp };
    const secret = this.params.secret(this.ctx!!);
    return jwt.sign(payload, secret, { algorithm: 'HS256' });
  }

  public async decodeJwt(token: string): Promise<Result<T, string>> {
    const secret = this.params.secret(this.ctx!!);
    try {
      if (!jwt.verify(token, secret, { algorithm: 'HS256' })) {
        return { error: 'token verify failed' };
      }
      const value = jwt.decode<T, {}>(token).payload;
      if (!value) {
        return { error: 'token verify failed' };
      }
      // user-validity check
      if (!await Promise.resolve(this.params.isValid!!(this.ctx!!, value))) {
        return { error: 'token failed extra validation' };
      }
      return { ok: true, value };
    } catch (e) {
      return { error: ''+e };
    }
  }
}
