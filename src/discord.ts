import { OAuth2Token, OAuth2Fetch } from "@badgateway/oauth2-client";
import { BasicProvider, ProviderConfig, ProviderSource } from ".";

export const API_BASE = 'https://discord.com/api/v10';
const SOURCE: ProviderSource = {
  name: 'discord',
  scope: ["identify", "email"],
  settings: {
    server: 'https://discord.com/api/oauth2/',
    authorizationEndpoint: './authorize',
    tokenEndpoint: './token',
    clientId: '',
  },
};

export class DiscordProvider extends BasicProvider {
  constructor(config: ProviderConfig) {
    super(SOURCE, config);
  }

  async getEmail(token: OAuth2Token): Promise<string> {
    const fetchFn = new OAuth2Fetch({
      client: this.client,
      getNewToken: () => token,
    });
    const data = await fetchFn.fetch(API_BASE+`/users/@me`)
      .then(r => r.json()) as Record<string,any>;
    return data.email;
  }
}