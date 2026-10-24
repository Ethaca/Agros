import { config } from './config.ts';
import type { ChangedFile } from './diff.ts';

const API = 'https://api.github.com';

export class GitHubError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function exchangeOAuthCode(code: string): Promise<string> {
  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: config.githubClientId,
      client_secret: config.githubClientSecret,
      code,
      redirect_uri: `${config.publicUrl}/auth/github/callback`,
    }),
  });
  const data = (await res.json()) as { access_token?: string; error_description?: string };
  if (!data.access_token) throw new Error(`GitHub OAuth 실패: ${data.error_description ?? res.status}`);
  return data.access_token;
}

export interface GhRepo { full_name: string; private: boolean; html_url: string; default_branch: string; permissions?: { admin?: boolean }; pushed_at: string }
export interface GhPull {
  number: number; title: string; body: string | null; html_url: string; draft: boolean;
  head: { sha: string }; base: { repo: { full_name: string } };
}

export class GitHub {
  constructor(private token: string) {}

  async request<T>(method: string, path: string, body?: unknown, accept = 'application/vnd.github+json'): Promise<T> {
    const res = await fetch(path.startsWith('http') ? path : API + path, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        Accept: accept,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'argos',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new GitHubError(res.status, `GitHub ${method} ${path} → ${res.status}: ${(await res.text()).slice(0, 300)}`);
    if (res.status === 204) return undefined as T;
    return (accept.includes('raw') ? await res.text() : await res.json()) as T;
  }

  private async paginate<T>(path: string, max = 1000): Promise<T[]> {
    const out: T[] = [];
    for (let page = 1; out.length < max; page++) {
      const sep = path.includes('?') ? '&' : '?';
      const items = await this.request<T[]>('GET', `${path}${sep}per_page=100&page=${page}`);
      out.push(...items);
      if (items.length < 100) break;
    }
    return out;
  }

  getUser() { return this.request<{ id: number; login: string; avatar_url: string }>('GET', '/user'); }

  async listAdminRepos(): Promise<GhRepo[]> {
    const all = await this.paginate<GhRepo>('/user/repos?sort=pushed&affiliation=owner,collaborator,organization_member', 300);
    return all.filter((r) => r.permissions?.admin);
  }

  getRepo(fullName: string) { return this.request<GhRepo>('GET', `/repos/${fullName}`); }

  createHook(fullName: string, url: string, secret: string) {
    return this.request<{ id: number }>('POST', `/repos/${fullName}/hooks`, {
      name: 'web', active: true, events: ['pull_request'],
      config: { url, content_type: 'json', secret, insecure_ssl: '0' },
    });
  }

  deleteHook(fullName: string, hookId: number) { return this.request<void>('DELETE', `/repos/${fullName}/hooks/${hookId}`); }

  getPull(fullName: string, n: number) { return this.request<GhPull>('GET', `/repos/${fullName}/pulls/${n}`); }

  listPulls(fullName: string) { return this.request<GhPull[]>('GET', `/repos/${fullName}/pulls?state=open&per_page=20`); }

  listPullFiles(fullName: string, n: number) { return this.paginate<ChangedFile>(`/repos/${fullName}/pulls/${n}/files`, 3000); }

  async listTreePaths(fullName: string, sha: string): Promise<string[]> {
    const tree = await this.request<{ tree: { path: string; type: string }[] }>('GET', `/repos/${fullName}/git/trees/${sha}?recursive=1`);
    return tree.tree.filter((entry) => entry.type === 'blob').map((entry) => entry.path);
  }

  getFileContent(fullName: string, path: string, ref: string) {
    const p = path.split('/').map(encodeURIComponent).join('/');
    return this.request<string>('GET', `/repos/${fullName}/contents/${p}?ref=${ref}`, undefined, 'application/vnd.github.raw+json');
  }

  createStatus(fullName: string, sha: string, state: 'pending' | 'success' | 'failure' | 'error', description: string, targetUrl?: string) {
    return this.request('POST', `/repos/${fullName}/statuses/${sha}`, {
      state, description: description.slice(0, 140), context: 'argos/security', target_url: targetUrl,
    });
  }

  createReview(fullName: string, n: number, sha: string, body: string, comments: { path: string; line: number; side: 'RIGHT'; body: string }[]) {
    return this.request('POST', `/repos/${fullName}/pulls/${n}/reviews`, { commit_id: sha, event: 'COMMENT', body, comments });
  }

  createIssue(fullName: string, title: string, body: string, labels: string[]) {
    return this.request<{ number: number; html_url: string }>('POST', `/repos/${fullName}/issues`, { title, body, labels });
  }

  async getBranchSha(fullName: string, branch: string): Promise<string> {
    const ref = await this.request<{ object: { sha: string } }>('GET', `/repos/${fullName}/git/ref/heads/${encodeURIComponent(branch)}`);
    return ref.object.sha;
  }

  createBranch(fullName: string, branch: string, sha: string) {
    return this.request('POST', `/repos/${fullName}/git/refs`, { ref: `refs/heads/${branch}`, sha });
  }

  /** 파일 내용과 blob sha (내용을 갱신할 때 필요) */
  getFile(fullName: string, path: string, ref: string) {
    const p = path.split('/').map(encodeURIComponent).join('/');
    return this.request<{ sha: string; content: string; encoding: string }>('GET', `/repos/${fullName}/contents/${p}?ref=${encodeURIComponent(ref)}`);
  }

  putFile(fullName: string, path: string, branch: string, message: string, contentBase64: string, sha: string) {
    const p = path.split('/').map(encodeURIComponent).join('/');
    return this.request('PUT', `/repos/${fullName}/contents/${p}`, { message, content: contentBase64, sha, branch });
  }

  createPull(fullName: string, pr: { title: string; head: string; base: string; body: string; draft: boolean }) {
    return this.request<{ number: number; html_url: string }>('POST', `/repos/${fullName}/pulls`, pr);
  }

  /** 마커가 있는 '내가 쓴' 코멘트만 갱신 (다른 사람이 마커를 흉내 낸 코멘트를 덮어쓰지 않도록) */
  async upsertIssueComment(fullName: string, n: number, marker: string, body: string, authorLogin: string) {
    const comments = await this.paginate<{ id: number; body: string; user: { login: string } }>(`/repos/${fullName}/issues/${n}/comments`, 500);
    const existing = comments.find((c) => c.user?.login === authorLogin && c.body?.includes(marker));
    if (existing) return this.request('PATCH', `/repos/${fullName}/issues/comments/${existing.id}`, { body });
    return this.request('POST', `/repos/${fullName}/issues/${n}/comments`, { body });
  }
}
