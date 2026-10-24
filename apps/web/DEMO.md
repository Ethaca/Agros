# 로컬 GitHub 연동 데모

기존 웹앱은 GitHub **OAuth App**으로 로그인한다. 기본은 PR 코드 분석이며, 실제 실행이 필요하면 [노트북 Docker Worker](../../docs/LOCAL_SANDBOX.md)를 추가한다. GitHub App 설치 방식은 별도 계획이다.

## 실행

저장소 루트에서 실행한다.

```bash
node apps/web/scripts/setup-demo.mjs
node apps/web/scripts/start-demo.mjs
```

별도 터미널에서 공개 HTTPS 터널을 연다. macOS에서는 `brew install cloudflared`로 설치할 수 있다.

```bash
cloudflared tunnel --url http://127.0.0.1:8787 --no-autoupdate
```

출력된 HTTPS 주소를 다음 명령에 넣는다.

```bash
node apps/web/scripts/setup-demo.mjs --url https://YOUR-TUNNEL.trycloudflare.com
```

설정 스크립트는 `.dev.vars`를 만들고 비어 있는 세션·암호화 키를 생성한다. 기존 키와 자격증명은 유지한다. 데모 보고서 언어는 영어(`REPORT_LANG=en`)로 설정한다. 한국어는 `.dev.vars`에서 `REPORT_LANG=ko`로 변경한다.

데모 실행 스크립트는 Wrangler의 로컬 DB 탐색·관측 API를 비활성화해 공개 터널로 노출되지 않도록 한다.

## GitHub OAuth 등록

1. <https://github.com/settings/applications/new>에서 OAuth App을 등록한다.
2. Homepage URL은 터널의 HTTPS 주소로 설정한다.
3. Authorization callback URL은 같은 주소 뒤에 `/auth/github/callback`을 붙인다.
4. Client ID와 생성한 Client Secret을 `apps/web/.dev.vars`의 `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`에 입력한다. Secret을 채팅이나 커밋에 넣지 않는다.
5. 로컬 서버를 재시작하고 **터널 주소로** 접속해 GitHub 로그인 → 테스트 저장소 보호 켜기 → PR 생성 순서로 확인한다.

`ANTHROPIC_API_KEY`는 선택 사항이다. 비어 있으면 정적 규칙만으로 검사하며, 입력하면 분석 대상 코드 일부가 Anthropic API로 전송된다.

## 권한과 재시작

- 로그인 시 `repo`, `admin:repo_hook`, `read:user` OAuth 권한을 요청한다. OAuth 권한은 저장소 하나에만 제한되지 않으므로 데모 전용 계정·테스트 저장소를 사용하는 것이 적절하다.
- 보호를 켤 저장소에는 관리자 권한이 필요하다. 조직 저장소는 조직의 OAuth 승인 정책도 적용된다.
- PR 댓글과 상태는 로그인한 사용자 명의로 게시된다. 이 데모에서는 고객 코드를 실행하지 않는다.
- `.dev.vars`는 Git에서 제외되며 파일 권한은 소유자 읽기·쓰기로 설정된다. 키를 바꾸면 기존 로그인 세션 또는 저장된 토큰을 사용할 수 없게 된다.
- Quick Tunnel을 다시 열면 주소가 바뀐다. 설정 스크립트와 OAuth App의 Homepage/Callback 주소를 갱신하고, 기존 보호 저장소는 보호 끄기 → 다시 켜기로 Webhook 주소를 갱신한다.
- 시연 중에는 서버와 터널 터미널을 모두 유지한다. 종료하려면 각각 `Ctrl+C`를 누른다. 필요하면 종료 전에 저장소 보호를 끄고 GitHub에서 OAuth 접근도 해제한다.

참고: [OAuth App 등록](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app), [Cloudflare Quick Tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
