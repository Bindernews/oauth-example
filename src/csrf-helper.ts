import { ISession } from ".";
import { date2unix, requestSet } from "./util";

export type RequestLike = Record<string, any>;

export interface CsrfConfig {
  /**
   * The session key to store the CSRF value in, MUST be stored server-side.
   * Default is 'csrf'.
   */
  sessKey: string,
  /**
   * The key to set on the request/context object.
   * Default is 'csrf'.
   */
  reqKey: string,
  /**
   * Key in the POST'ed form data, used in {@link CsrfHelper.checkForm}.
   * Default is 'csrf'.
   */
  formKey: string,
  /**
   * Number of seconds the CSRF token should live.
   * Default is 24 hours.
   */
  ttl: number,

  /**
   * Function to set a key/value pair on the request object.
   */
  set: (req: Record<string,any>, k: string, v: any) => void,
}

export const CSRF_DEFAULT: CsrfConfig = {
  sessKey: 'csrf',
  reqKey: 'csrf',
  formKey: 'csrf',
  ttl: 60*60*24,
  set: requestSet,
}

export class CsrfHelper {
  private c: CsrfConfig;

  constructor(
    public session: ISession,
    config: CsrfConfig,
  ) {
    this.c = config;
  }

  /**
   * Initialize the CSRF value if it doesn't exist,
   * and then add it to the request object.
   * 
   * @param req the {@link Request} or context object.
   */
  async create(req: RequestLike) {
    let csrfValue = await this.session.get<string>(this.c.sessKey) || '';
    if (!csrfValue) {
      csrfValue = crypto.randomUUID();
      const exp = date2unix(new Date()) + this.c.ttl;
      await this.session.put(this.c.sessKey, csrfValue, exp);
    }
    this.c.set(req, this.c.reqKey, csrfValue);
  }
  
  /**
   * Parse the request body as form data and get the client's CSRF
   * key from that. Then call {@link checkValue}.
   * 
   * Note: You can create a new {@link Request} object using the initial request's body.
   * 
   * @param req the {@link Request} object with an un-parsed body
   * @returns result of {@link checkValue}
   */
  async checkForm(req: Request): Promise<boolean> {
    return req.formData()
      .then(form => form.get(this.c.formKey) || '')
      .then(this.checkValue);
  }

  /**
   * Check to ensure that the client's csrf token matches the server's expected value.
   * 
   * @param csrf the client-sent CSRF token
   * @returns `true` iff the client's csrf token matches the server's csrf token
   */
  async checkValue(csrf: string): Promise<boolean> {
    let csrfValue = await this.session.get<string>(this.c.sessKey) || '';
    if (!csrfValue) {
      return false;
    }
    return csrf === csrfValue;
  }
}