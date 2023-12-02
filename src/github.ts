import { OAuth2Token, OAuth2Fetch } from "@badgateway/oauth2-client";
import { BasicProvider, ProviderSource, ProviderConfig } from ".";

const SOURCE: ProviderSource = {
  name: 'github',
  scope: ['user:email'],
  settings: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    clientId: '',
  }
};

const API_HEADERS = {
  'Accept': "application/vnd.github+json",
  'X-GitHub-Api-Version': "2022-11-28",
};

export class GithubProvider extends BasicProvider {
  constructor(config: ProviderConfig) {
    super(SOURCE, config);
  }

  async getEmail(token: OAuth2Token): Promise<string> {
    const API_URL = 'https://api.github.com/user/emails';
    const fetchFn = new OAuth2Fetch({
      client: this.client,
      getNewToken: () => token,
    });
    const data = await fetchFn.fetch(API_URL, { headers: API_HEADERS })
      .then(r => r.json()) as {email: string, primary: boolean}[];
    for (const e of data) {
      if (e.primary) {
        return e.email;
      }
    }
    throw new Error('unable to determine email')
  }
}
