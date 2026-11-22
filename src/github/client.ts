export class GitHubError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** Minimal GitHub REST client. The token only ever goes in the Authorization header. */
export class GitHub {
  /** last seen X-RateLimit-Remaining, if any */
  remaining?: number;
  constructor(private token?: string, private base = "https://api.github.com") {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "gitward",
    };
    if (this.token) h.authorization = `Bearer ${this.token}`;
    return h;
  }

  async get<T>(path: string): Promise<{ data: T; next?: string }> {
    const url = path.startsWith("http") ? path : this.base + path;
    // pagination links come from response headers; never let them send the token anywhere but GitHub's API
    if (new URL(url).origin !== new URL(this.base).origin) throw new GitHubError(0, `refusing to send credentials to ${new URL(url).origin}`);
    const res = await fetch(url, { headers: this.headers() });
    const rem = res.headers.get("x-ratelimit-remaining");
    if (rem !== null) this.remaining = Number(rem);
    if (!res.ok) {
      const left = res.headers.get("x-ratelimit-remaining");
      const reset = Number(res.headers.get("x-ratelimit-reset"));
      const hint = (res.status === 403 || res.status === 429) && left === "0"
        ? ` (rate limit exhausted${reset ? `, resets ${new Date(reset * 1000).toLocaleTimeString()}` : ""}` +
          `${this.token ? "" : "; sign in with --account for a much higher limit"})`
        : "";
      throw new GitHubError(res.status, `GET ${new URL(url).pathname} -> ${res.status}${hint}`);
    }
    const link = res.headers.get("link") ?? "";
    const next = /<([^>]+)>;\s*rel="next"/.exec(link)?.[1];
    return { data: (await res.json()) as T, next };
  }

  /** POST/PATCH/PUT/DELETE with a JSON body. Used only by the opt-in cleaner. */
  async send<T>(method: "POST" | "PATCH" | "PUT" | "DELETE", path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.base + path, {
      method,
      headers: { ...this.headers(), "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      let msg = "";
      try { msg = ((await res.json()) as { message?: string }).message ?? ""; } catch { /* no body */ }
      throw new GitHubError(res.status, `${method} ${path} -> ${res.status} ${msg}`.trim());
    }
    return (res.status === 204 ? undefined : await res.json()) as T;
  }

  async paginate<T>(path: string, max = 20): Promise<T[]> {
    const out: T[] = [];
    let url: string | undefined = path;
    for (let i = 0; url && i < max; i++) {
      const page: { data: T[]; next?: string } = await this.get<T[]>(url);
      out.push(...page.data);
      url = page.next;
    }
    return out;
  }
}
