import { DEFAULT_LANG, type Lang } from './i18n.ts';
import type { Category } from './types.ts';

export interface LearningGuide {
  concept: string;
  misconception: string;
  question: string;
  answer: string;
  checks: string[];
}

/** 실행 여부와 무관한 교육 자료. 검사 결과나 서비스의 안전성을 보증하지 않는다. */
const GUIDES: Record<Category, LearningGuide> = {
  API1: {
    concept: '인증은 “누구인가”, 객체 인가는 “이 데이터에 접근해도 되는가”를 확인합니다. 로그인한 사용자도 다른 사람의 데이터에는 접근할 수 없어야 합니다.',
    misconception: '로그인 미들웨어가 있거나 ID가 UUID이면 소유권 검사도 해결됐다고 생각하기 쉽습니다. ID의 예측 난이도와 접근 권한은 별개입니다.',
    question: 'A와 B가 모두 로그인했습니다. B가 A의 주문 ID로 요청하면 어떤 결과여야 할까요?',
    answer: '정책상 공유되지 않은 주문이라면 데이터가 반환되거나 수정되지 않아야 합니다. 서버에서 인증된 사용자·테넌트와 객체의 관계를 검사해야 합니다.',
    checks: ['사용자 식별자를 body가 아닌 검증된 세션에서 얻는지 확인', '조회뿐 아니라 수정·삭제에도 소유권 조건 적용', '본인 요청 성공 + 타인 요청 거부를 함께 테스트'],
  },
  API2: {
    concept: '토큰을 읽는 것과 신뢰할 수 있는 토큰인지 검증하는 것은 다릅니다. 서명·만료·발급자 등 서비스가 요구하는 조건을 확인해야 인증에 사용할 수 있습니다.',
    misconception: 'AI가 만든 코드에서 jwt.decode()가 사용자 정보를 돌려주면 인증도 끝났다고 착각할 수 있습니다. 디코딩은 서명 검증이 아닙니다.',
    question: '내용을 읽을 수 있는 JWT라면 그 안의 userId를 바로 신뢰해도 될까요?',
    answer: '아니요. 신뢰하는 키와 허용 알고리즘으로 서명을 검증하고 만료 등 필요한 조건을 검사한 뒤 사용해야 합니다.',
    checks: ['라우터 상위의 인증 미들웨어까지 확인', '서명 변조·만료·누락 토큰을 거부하는지 테스트', '정상 토큰의 요청도 계속 성공하는지 확인'],
  },
  API3: {
    concept: '객체에 접근할 권한이 있어도 모든 필드를 읽거나 수정할 권한이 있는 것은 아닙니다. 입력 필드와 응답 필드를 각각 제한해야 합니다.',
    misconception: '프론트엔드 폼에 role 필드가 없으면 사용자가 보낼 수 없다고 생각하기 쉽습니다. 클라이언트 요청은 직접 만들 수 있습니다.',
    question: '프로필 수정 API에 예상하지 않은 role 필드를 추가해 보내면 어떻게 처리해야 할까요?',
    answer: '일반 사용자가 바꿀 수 있는 필드만 서버에서 명시적으로 선택해야 합니다. role 등 권한 필드는 별도의 인가된 흐름으로 처리해야 합니다.',
    checks: ['req.body 전체를 DB에 넘기지 않는지 확인', '응답 DTO에 필요한 필드만 포함', '추가한 금지 필드가 저장되거나 응답에 노출되지 않는지 검사'],
  },
  API4: {
    concept: '정상 요청도 횟수·크기·실행 시간이 무제한이면 서버 자원과 외부 API 비용을 소모할 수 있습니다.',
    misconception: '페이지네이션이나 로그인 기능이 있다는 것만으로 자원 사용량이 제한되지는 않습니다. limit의 최대값도 서버에서 정해야 합니다.',
    question: 'limit=1000000을 요청하면 서버가 그 값을 그대로 사용해도 될까요?',
    answer: '서비스에 맞는 상한을 적용하거나 요청을 거부해야 합니다. 사용자별 빈도 제한과 타임아웃도 별도로 고려해야 합니다.',
    checks: ['입력 크기·페이지 크기·실행 시간에 상한 설정', '민감한 작업의 사용자별 호출 제한 확인', '격리된 테스트에서 경계값과 제한 초과 응답 확인'],
  },
  API5: {
    concept: '기능 인가는 이 사용자가 관리자 작업 같은 특정 행동을 할 수 있는지 서버에서 검사하는 것입니다.',
    misconception: '관리자 버튼을 숨기거나 x-role: admin 헤더를 확인하는 것으로 권한이 보호되지는 않습니다. 헤더는 사용자가 바꿀 수 있습니다.',
    question: '일반 사용자가 관리자 API 주소를 알고 직접 요청한다면 무엇이 막아야 할까요?',
    answer: '서버가 관리하는 역할·권한 정보에 따른 기능 인가가 막아야 합니다. UI 표시 여부나 클라이언트가 주장하는 역할은 근거가 아닙니다.',
    checks: ['역할의 출처가 서버 또는 검증된 클레임인지 확인', '모든 특권 엔드포인트에 역할 검사 적용', '관리자 성공 + 일반 사용자 거부 테스트'],
  },
  API6: {
    concept: '개별 요청이 유효해도 예약·쿠폰·구매 같은 업무 흐름을 반복하거나 동시에 실행하면 비즈니스 규칙을 악용할 수 있습니다.',
    misconception: '로그인한 사용자의 정상 형식 요청이면 업무적으로도 안전하다고 생각하기 쉽습니다.',
    question: '일회용 쿠폰을 같은 사용자가 동시에 두 번 요청하면 두 번 적용돼도 될까요?',
    answer: '아니요. 서비스 정책에 따라 원자적 상태 변경·중복 방지·사용량 제한으로 한 번만 적용되게 해야 합니다.',
    checks: ['반복·동시 실행의 업무상 제한 정의', '중복 방지와 트랜잭션 경계 확인', '격리된 환경에서 중복 요청 결과 확인'],
  },
  API7: {
    concept: '서버가 사용자의 URL을 가져오면 사용자는 자신의 브라우저 대신 서버의 네트워크 접근 권한을 이용하게 됩니다.',
    misconception: 'https로 시작하거나 URL 문법이 올바르면 안전하다고 생각하기 쉽습니다. 목적지 IP와 리다이렉트는 별도 문제입니다.',
    question: '허용된 URL이 내부 주소로 리다이렉트되면 처음 URL만 검사해도 충분할까요?',
    answer: '아니요. 최종 목적지와 각 리다이렉트, DNS 해석 결과까지 정책에 맞게 제한해야 합니다. 가능하면 허용된 목적지만 요청하세요.',
    checks: ['허용 도메인·프로토콜을 명시', '사설·루프백·링크로컬 주소와 리다이렉트 제한', '실제 내부망 대신 모의 목적지로 차단 정책 테스트'],
  },
  API8: {
    concept: '디버그·오류 응답·CORS 같은 설정도 외부에 공개되는 정보와 브라우저의 접근 범위를 결정합니다.',
    misconception: 'CORS를 전체 허용하면 언제나 인증이 우회된다는 설명도 틀립니다. Origin·쿠키·자격증명 설정과 브라우저 동작을 함께 봐야 합니다.',
    question: 'CORS 제한을 설정하면 브라우저 밖에서 보낸 비인가 요청도 막힐까요?',
    answer: '아니요. CORS는 인증·인가를 대신하지 않습니다. 서버의 접근 제어는 별도로 유지해야 합니다.',
    checks: ['운영 설정에서 디버그와 상세 오류 비공개', '허용 Origin과 자격증명 정책을 함께 확인', '오류 응답과 실제 브라우저 접근을 각각 검증'],
  },
  API9: {
    concept: '오래된 버전이나 디버그 API도 배포되어 접근 가능하면 보호와 관리가 필요한 공격 표면입니다.',
    misconception: 'UI에서 링크를 제거하면 엔드포인트도 사용할 수 없게 된다고 생각하기 쉽습니다.',
    question: '프론트에서 더 이상 쓰지 않는 /v0 API를 서버에 그대로 남겨도 될까요?',
    answer: '사용 여부와 별개로 접근 가능성을 확인해야 합니다. 제거하거나 현재와 같은 보호·인벤토리 관리에 포함해야 합니다.',
    checks: ['배포된 라우트 목록과 관리 목록 비교', '이전 버전·디버그 라우트의 보호 확인', '운영 빌드에서 제거 또는 접근 거부 여부 확인'],
  },
  API10: {
    concept: '외부 API의 응답도 신뢰 경계를 넘는 입력입니다. 통신 상대와 데이터 형식을 검증해야 합니다.',
    misconception: '익숙한 외부 서비스의 응답이거나 HTTPS를 쓰면 검증이 필요 없다고 생각하기 쉽습니다. 인증서 검증을 끄면 상대를 확인하지 못합니다.',
    question: '인증서 오류를 피하려고 verify=false로 바꾸는 것이 올바른 해결일까요?',
    answer: '아니요. 인증서 체인과 신뢰 설정을 바로잡아야 합니다. 필요한 경우 특정 사설 CA를 신뢰하도록 구성하세요.',
    checks: ['TLS 인증서 검증 유지', '외부 응답의 스키마·크기·타임아웃 제한', '모의 외부 API의 비정상 응답 처리 확인'],
  },
  INJECTION: {
    concept: '입력이 쿼리나 명령의 구조로 해석되는 순간, 사용자가 원래 허용하지 않은 동작을 바꿀 수 있습니다.',
    misconception: 'AI가 만든 문자열 조합 코드가 정상 입력에서 잘 동작해도 안전한 쿼리라는 뜻은 아닙니다.',
    question: '사용자 입력의 따옴표를 제거하는 것만으로 쿼리를 안전하게 만들 수 있을까요?',
    answer: '입력을 임의로 손질하기보다 바인딩 파라미터로 데이터와 쿼리 구조를 분리해야 합니다. NoSQL 필터도 필드와 타입을 제한해야 합니다.',
    checks: ['쿼리는 바인딩 파라미터 사용', '필터의 필드·타입·연산자 제한', '격리된 DB에서 특수 문자가 데이터로 처리되는지 확인'],
  },
  SECRETS: {
    concept: '키를 코드에 넣으면 저장소·로그·히스토리를 통해 권한 자체가 유출될 수 있습니다.',
    misconception: '키가 든 줄을 삭제하거나 저장소를 비공개로 바꾸면 노출된 키도 안전해진다고 생각하기 쉽습니다.',
    question: '커밋에 포함된 키를 다음 커밋에서 지웠다면 조치가 끝났을까요?',
    answer: '아니요. 실제 자격 증명이었다면 폐기·재발급하고 사용 기록을 확인해야 합니다. 새 키는 비밀 저장소에서 주입해야 합니다.',
    checks: ['실제 키인지 확인 후 노출된 키 폐기·교체', '코드·로그·예제에 자격 증명을 남기지 않기', '이전 키 사용 실패와 새 키의 최소 권한 확인'],
  },
};

const GUIDES_EN: Record<Category, LearningGuide> = {
  API1: {
    concept: 'Authentication checks "who are you"; object authorization checks "may you access this data". A logged-in user still must not reach someone else\'s data.',
    misconception: 'It is easy to assume that a login middleware or UUID IDs also solve ownership checks. How hard an ID is to guess has nothing to do with access rights.',
    question: 'A and B are both logged in. What should happen when B sends a request with A\'s order ID?',
    answer: 'If the order is not shared by policy, no data should be returned or changed. The server must check the relationship between the authenticated user/tenant and the object.',
    checks: ['Confirm the user identifier comes from the verified session, not the body', 'Apply the ownership condition to updates and deletes, not just reads', 'Test both an owner request that succeeds and another user\'s request that is denied'],
  },
  API2: {
    concept: 'Reading a token is different from verifying that it can be trusted. Only after checking the signature, expiry, issuer and other required conditions can it be used for authentication.',
    misconception: 'When AI-generated code gets user info back from jwt.decode(), it is easy to think authentication is done. Decoding is not signature verification.',
    question: 'If you can read a JWT\'s contents, can you trust the userId inside it right away?',
    answer: 'No. Verify the signature with a trusted key and allowed algorithms, check expiry and other required conditions, and only then use it.',
    checks: ['Check the authentication middleware above the router as well', 'Test that tampered, expired and missing tokens are rejected', 'Confirm requests with a valid token still succeed'],
  },
  API3: {
    concept: 'Permission to access an object does not mean permission to read or modify every field. Limit input fields and response fields separately.',
    misconception: 'It is easy to think users cannot send a role field because the frontend form has none. Clients can craft requests directly.',
    question: 'How should a profile update API handle an unexpected role field added to the request?',
    answer: 'The server must explicitly select only the fields a regular user may change. Permission fields such as role belong to a separately authorized flow.',
    checks: ['Confirm the whole req.body is not passed to the DB', 'Include only the needed fields in the response DTO', 'Check that an added forbidden field is neither stored nor exposed in the response'],
  },
  API4: {
    concept: 'Even legitimate requests can drain server resources and external API budgets if their count, size or run time is unlimited.',
    misconception: 'Having pagination or a login does not by itself limit resource use. The server must also set the maximum for limit.',
    question: 'If a client requests limit=1000000, should the server use that value as-is?',
    answer: 'Apply an upper bound that fits the service or reject the request. Per-user rate limits and timeouts need separate consideration.',
    checks: ['Set upper bounds on input size, page size and run time', 'Check per-user call limits on sensitive operations', 'In an isolated test, check boundary values and the over-limit response'],
  },
  API5: {
    concept: 'Function-level authorization means the server checks whether this user may perform a specific action, such as an admin task.',
    misconception: 'Hiding the admin button or checking an x-role: admin header does not protect a permission. Users can change headers.',
    question: 'If a regular user knows an admin API path and calls it directly, what should stop them?',
    answer: 'Function-level authorization based on server-managed roles and permissions. Whether the UI shows a button, or what role the client claims, is not evidence.',
    checks: ['Confirm the role comes from the server or a verified claim', 'Apply the role check to every privileged endpoint', 'Test admin success and regular-user denial'],
  },
  API6: {
    concept: 'Even when each request is valid, repeating or running business flows such as bookings, coupons or purchases concurrently can abuse business rules.',
    misconception: 'It is easy to think a well-formed request from a logged-in user is also safe from a business point of view.',
    question: 'If the same user redeems a single-use coupon twice at the same time, may it be applied twice?',
    answer: 'No. Depending on policy, use atomic state changes, duplicate prevention and usage limits so it applies only once.',
    checks: ['Define business limits on repeated and concurrent execution', 'Check duplicate prevention and transaction boundaries', 'Check the result of duplicate requests in an isolated environment'],
  },
  API7: {
    concept: 'When the server fetches a user\'s URL, the user borrows the server\'s network access instead of their own browser\'s.',
    misconception: 'It is easy to think a URL is safe if it starts with https or is syntactically valid. The destination IP and redirects are separate problems.',
    question: 'If an allowed URL redirects to an internal address, is checking only the first URL enough?',
    answer: 'No. Restrict the final destination, every redirect and the DNS resolution result according to policy. Where possible, request only allowed destinations.',
    checks: ['Specify allowed domains and protocols', 'Restrict private, loopback and link-local addresses and redirects', 'Test the blocking policy against a mock destination instead of the real internal network'],
  },
  API8: {
    concept: 'Settings such as debug mode, error responses and CORS also decide what is exposed externally and what browsers may access.',
    misconception: 'The claim that allowing all CORS origins always bypasses authentication is also wrong. Origin, cookie and credential settings must be read together with browser behavior.',
    question: 'If you set CORS restrictions, are unauthorized requests sent from outside a browser blocked too?',
    answer: 'No. CORS does not replace authentication or authorization. Server-side access control must stay in place separately.',
    checks: ['Keep debug mode and detailed errors private in production settings', 'Check allowed origins together with the credential policy', 'Verify error responses and real browser access separately'],
  },
  API9: {
    concept: 'Old versions and debug APIs are attack surface that needs protection and management whenever they are deployed and reachable.',
    misconception: 'It is easy to think an endpoint becomes unusable once its link is removed from the UI.',
    question: 'Can a /v0 API the frontend no longer uses stay on the server as-is?',
    answer: 'Check whether it is reachable regardless of use. Remove it, or bring it under the same protection and inventory management as the current API.',
    checks: ['Compare the deployed route list with the managed inventory', 'Check protection on old-version and debug routes', 'Confirm they are removed or denied in production builds'],
  },
  API10: {
    concept: 'Responses from external APIs are also input crossing a trust boundary. Verify the peer and the data format.',
    misconception: 'It is easy to think responses from a familiar service, or over HTTPS, need no validation. Turning off certificate verification means the peer is not verified.',
    question: 'Is switching to verify=false the right way to get past a certificate error?',
    answer: 'No. Fix the certificate chain and trust settings. If needed, configure trust for the specific private CA.',
    checks: ['Keep TLS certificate verification on', 'Limit schema, size and timeout of external responses', 'Check handling of malformed responses from a mock external API'],
  },
  INJECTION: {
    concept: 'Once input is interpreted as part of a query or command structure, a user can change behavior that was never allowed.',
    misconception: 'AI-generated string-building code working fine on normal input does not make the query safe.',
    question: 'Can removing quotes from user input alone make a query safe?',
    answer: 'Instead of ad hoc input cleanup, separate data from query structure with bound parameters. NoSQL filters also need restricted fields and types.',
    checks: ['Use bound parameters for queries', 'Restrict filter fields, types and operators', 'Confirm special characters are treated as data in an isolated DB'],
  },
  SECRETS: {
    concept: 'Putting a key in code can leak the permission itself through the repository, logs and history.',
    misconception: 'It is easy to think a leaked key is safe once the line is deleted or the repository is made private.',
    question: 'If a key included in a commit is removed in the next commit, is the issue resolved?',
    answer: 'No. If it was a real credential, revoke and reissue it and review its usage history. Inject the new key from a secret store.',
    checks: ['After confirming it is a real key, revoke and replace the exposed key', 'Do not leave credentials in code, logs or examples', 'Confirm the old key fails and the new key has least privilege'],
  },
};

export function learningGuide(category: Category, lang: Lang = DEFAULT_LANG): LearningGuide {
  const guides = lang === 'ko' ? GUIDES : GUIDES_EN;
  return Object.hasOwn(guides, category) ? guides[category] : guides.API8;
}

export function learningSource(category: Category): string {
  if (category === 'SECRETS') return 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html';
  if (category === 'INJECTION') return 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html';
  return 'https://api-security.owasp.org/editions/2023/en/0x11-t10/';
}

export function reviewPrompt(category: Category, lang: Lang = DEFAULT_LANG): string {
  const checks = learningGuide(category, lang).checks.join('. ');
  if (lang === 'ko') {
    return `이 변경의 ${category} 보안을 검토해 주세요. ${checks}. 각 판단의 코드 위치와 근거를 보여주고, 확인할 수 없는 부분은 가정으로 구분해 주세요. 테스트 코드를 제안하되 실제로 실행하지 않은 결과를 통과했다고 표현하지 마세요.`;
  }
  return `Please review this change for ${category} security. ${checks}. Show the code location and evidence for each judgment, and mark anything you cannot confirm as an assumption. Suggest test code, but do not describe results you did not actually run as passing.`;
}
