import { OAuth2Client, OAuth2Token, generateCodeVerifier } from "@badgateway/oauth2-client";
import { ClientSettings } from "@badgateway/oauth2-client/dist/client";
import { parse, serialize } from 'cookie';
import { date2unix } from "./util";

const SESS_KEY = 'oa2p-code';
const STATE_KEY = 'oa2p-state';

export interface ProviderConfig {
  /**
   * Oauth2 client ID
   */
  clientId: string,
  /**
   * Oauth2 client secret
   */
  clientSecret?: string,
  /**
   * The URL for the provider to redirect to with the authorization code.
   */
  callbackUrl: string,
  /**
   * Session storage
   */
  session: ISession,
}

export interface ISession {
  /**
   * Set some key-value in the session state.
   * The key may be prefixed, modified, etc. as long as the modified
   * key is consistent.
   * 
   * @param key key
   * @param value object to store (safe to json serialize)
   * @param expires optional unix timestamp when this value should expire
   */
  put<T>(key: string, value: T, expires?: number): Promise<void>;
  /**
   * Retrieve the given key from the current session.
   * Returns `null` if the key is not found.
   */
  get<T>(key: string): Promise<T|null>;
  /**
   * Delete the given key.
   */
  delete(key: string): Promise<void>;
}

export interface ProviderSource {
  /** The provider name/id */
  name: string,
  /** List of oauth scopes to query */
  scope: string[],
  /** client settings, without clientId or clientSecret */
  settings: ClientSettings&{ clientId: '' },
}

export abstract class BasicProvider {
  public client: OAuth2Client;

  constructor(
    private source: ProviderSource,
    public config: ProviderConfig,
  ) {
    this.client = new OAuth2Client({
      ...source.settings,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
    });
  }

  /** Provider name or id */
  public get name(): string { return this.source.name; }

  async authRedirect(req: Request): Promise<Response> {
    const codeVerifier = await generateCodeVerifier();
    const state = await generateCodeVerifier();
    // create the expire timestamp (now + 10 minutes).
    const exp = date2unix(new Date()) + (60 * 10);
    // Store code verifier in the session
    await this.config.session.put(SESS_KEY, { codeVerifier, exp }, exp);
    // Determine redirect url
    const destUrl = await this.client.authorizationCode.getAuthorizeUri({
      redirectUri: this.config.callbackUrl,
      state,
      codeVerifier,
      scope: this.source.scope,
    });
    const headers = {
      'Set-Cookie': serialize(STATE_KEY, state, { httpOnly: true }),
      'Content-Type': 'text/html; charset=UTF-8',
    };
    return new Response(makeRedirectPage(destUrl), { headers });
  }

  async getTokenFromCode(req: Request): Promise<OAuth2Token|null> {
    // Grab and delete the session data
    const sess: Record<string,any>|null = await this.config.session.get(SESS_KEY);
    await this.config.session.delete(SESS_KEY);
    if (!sess) {
      return null;
    }
    // Check expiry
    const now = date2unix(new Date());
    if (now > sess.exp) {
      return null;
    }
    // Parse cookies to get state
    const cookies = parse(req.headers.get('Cookie') || '');
    const state = cookies[STATE_KEY] || '';
    return this.client.authorizationCode.getTokenFromCodeRedirect(req.url, {
      redirectUri: this.config.callbackUrl,
      codeVerifier: sess.codeVerifier,
      state,
    });
  }

  abstract getEmail(token: OAuth2Token): Promise<string>;
}

function makeRedirectPage(destUrl: string): string {
  return `<!DOCTYPE html><html><body>
If you are not redirected automatically <a href="${destUrl}">click here</a>.
<script>window.location = "${destUrl}";</script>
</body></html>`;
}

