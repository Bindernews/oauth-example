import { Context, Hono, MiddlewareHandler, Next } from 'hono'
import { html } from 'hono/html';
import { createMiddleware } from 'hono/factory';
import { JwtManager } from '../src/jwt-middleware';
import { hasAll } from '../src/util';
import { SESSION_DEFAULT, sessionMiddleware } from '../src/hono/session';
import { CSRF_DEFAULT, CsrfHelper } from '../src/csrf-helper';
import { BasicProvider, ISession } from '../src';
import { KVSessionStorage } from '../src/cf-kv-session';
import { DiscordProvider } from '../src/discord';
import { GithubProvider } from '../src/github';

type LogoutState = { timestamp: number }|null;
type AppEnv = {
  Bindings: {
    OAUTH_STATE: KVNamespace,
    AUTH_CONFIG: KVNamespace,
    JWT_SECRET: string,
  } & Record<string,string>,
  Variables: {
    auth: AuthStorage,
    csrf: string,
    sessionId: string,
  },
}

export interface AuthStorage {
  email: string,
  scope: string[],
}

const PROVIDERS = ['discord'];

const jwtMgr = new JwtManager<AuthStorage, Context<AppEnv>>({
  cookie: '_auth',
  allowBearer: true,
  secret(ctx) { return ctx.env.JWT_SECRET; },
  async isValid(ctx, payload) {
    if (!payload.iat) {
      return false;
    }
    const obj = await ctx.env.OAUTH_STATE.get<LogoutState>(`${payload.email}/logout`, 'json');
    return !(obj && obj.timestamp >= payload.iat!!);
  },
});

function mwLoadJwt(required: boolean): MiddlewareHandler<AppEnv> {
  return createMiddleware<AppEnv>(async (c, next) => {
    const mgr = jwtMgr.withContext(c);
    const token = await mgr.safeGetToken(c.req.raw);
    if (token) {
      c.set('auth', token);
    } else if (required) {
      // If the token was required, redirect to the login url
      const origin = new URL(c.req.url);
      return c.redirect(origin+'/login', 303);
    }
    await next();
  });
}

function mwAuthorized(scope: string[]): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const auth = c.var.auth;
    if (!auth) {
      console.error('mwAuthorized requires mwLoadJwt');
      return new Response(null, { status: 500 });
    }
    if (!hasAll(auth.scope, scope)) {
      return c.html(html`<!DOCTYPE html><html><body><h2>Unauthorized</h2></body></html>`);
    }
    await next();
  };
}

async function mwCsrfCheck(c: Context<AppEnv>, next: Next) {
  await new CsrfHelper(createSession(c), CSRF_DEFAULT).checkForm(c.req.raw);
  await next();
}

async function mwCsrfCreate(c: Context<AppEnv>, next: Next) {
  await new CsrfHelper(createSession(c), CSRF_DEFAULT).create(c);
  await next();
}

function createSession(c: Context<AppEnv>): ISession {
  return new KVSessionStorage(c.env.OAUTH_STATE, s => `${c.var.sessionId}/${s}`)
}

function makeProvider(name: string, c: Context<AppEnv>): BasicProvider {
  const origin = new URL(c.req.url).origin;
  const opts = {
    clientId: c.env[name+'_client_id'],
    clientSecret: c.env[name+'_client_secret'],
    callbackUrl: origin+`/auth/${name}/`,
    session: createSession(c),
  };
  switch (name) {
    case 'discord': return new DiscordProvider(opts);
    case 'github': return new GithubProvider(opts);
    default: throw new Error('invalid provider');
  }
}

const app = new Hono<AppEnv>();
app.use('*', sessionMiddleware(SESSION_DEFAULT));
app.get('/', (c) => c.text('Hello Hono!'))
app.use('/login', mwCsrfCreate, mwLoadJwt(false))
  .get((c) => {
  const csrf = c.var.csrf;
  let logoutCode = undefined;
  if (c.var.auth) {
    logoutCode = html`
    <form action="/logout" method="post">
      <input type="hidden" name="csrf" value="${csrf}" />
      <input type="submit" value="Logout" />
    </form>`;
  }

  return c.html(html`
    <ul>
      <li><a href="/auth/discord/?out=1">Login with Discord</a></li>
    </ul>
    ${logoutCode}
  `);
});
app.post('/logout', mwCsrfCheck, (c) => {
  const mgr = jwtMgr.withContext(c);
  c.header('set-cookie', mgr.clearCookie());
  return c.redirect('/login', 303);
});

app.get('/secret',
  mwLoadJwt(true),
  mwAuthorized(['secret:view']),
  async (c) => {
    return c.html(html`<!DOCTYPE html><html><body>It's a secret to everybody!</body></html>`);
  },
);

for (const provider of PROVIDERS) {
  app.get(`/auth/${provider}/`, async (c) => {
    // console.log(c.req.raw.headers)
    const prov = makeProvider(provider, c);
    if (c.req.query('out')) {
      return await prov.authRedirect(c.req.raw);
    } else {
      try {
        const oaToken = await prov.getTokenFromCode(c.req.raw);
        // console.log('got redirect', token);
        if (!oaToken) {
          throw new Error('did not obtain token');
        }
        const email = await prov.getEmail(oaToken);
        if (!email) {
          throw new Error('did not obtain email');
        }
        const auth_data = await c.env.AUTH_CONFIG.get<AuthStorage>(email, 'json');
        if (!auth_data) {
          throw new Error('unknown user');
        }
        const mgr = jwtMgr.withContext(c);
        const jwToken = await mgr.createJwt({
          email,
          scope: auth_data.scope,
        });
        const origin = new URL(c.req.url).origin;
        return mgr.setCookie(c.req.raw, jwToken, origin+'/login');
      } catch (e) {
        console.log(e);
        return c.html(`<!DOCTYPE html><html><body>Error during authentication. Please try again.</body></html>`);
      }
    }
  });
}

export default app
