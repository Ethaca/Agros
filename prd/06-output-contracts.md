# 06. 출력 계약

`scan`은 `--out`(기본 `out/`)에 세 파일을 쓴다. A의 `report`와 CI가 읽는 입력이다. 스키마는 `src/types.ts`(Zod), **실제 예시와 필드 설명은 `examples/out/`**(테스트가 최신 상태를 지킨다).

| 파일 | 내용 | 스키마 |
|---|---|---|
| `matrix.json` | 칸마다 `persona`, `resource`, `target`, `expected`, `observed`, `verdict`, `evidence` | `Matrix` |
| `findings.json` | 점검별 발견(🟢·⚪ 포함). `secrets`는 `column` 또는 `env` | `Finding[]` |
| `scan-meta.json` | 증빙 헤더 재료 | `ScanMeta` |

## `scan-meta.json` (증빙 헤더 재료)
도구 버전, 실행 시각(UTC)·소요 시간, 대상 이름, 모드, **격리 방식과 이미지**, **미확인(`ai-draft`) 설정 필드 목록(`unconfirmed`)**, 설정 파일·시드 스키마의 SHA-256, 점검·페르소나·**시험한 리소스 목록**, 판정별 개수, `matrix.json`·`findings.json`의 SHA-256. 리포트는 해시를 직접 계산하지 않고 이 파일을 읽으면 된다.
- 해시는 파일을 **고정**할 뿐 위·변조를 막지 않는다(한계 문구에 명시).
- 시험한 리소스 목록이 곧 범위다. **여기 없는 라우트는 시험하지 않았다.**
- 절대 경로·토큰·마커 전체 값은 없다.

## 출력에 절대 싣지 않는 것
- 마커·비밀·환경 카나리의 전체 값(앞 6자만, 정적 스캔은 앞 4자 + 길이).
- 호스트 홈 경로, `PATH` 등 환경 정보(환경 덤프 응답은 본문 자체를 `body withheld`로 대체).
- 정적 스캔에서는 소스 줄 원문.
이 규칙은 시나리오 S9(스캔·수정 출력 파일과 터미널 출력 전체 검사)와 단위 테스트가 지킨다.

## 종료 코드
`0` 정상(🔴이 없거나 `mode: report`) · `1` 오류(설정, 기동 실패, 도커 없음, 시한 초과) · `2` `mode: block`이고 🔴이 있을 때.

## 계약을 바꿀 때
`MatrixCell.target`, `SeedManifest.ids`/`envCanaries`, `ScanMeta`(격리 필드 포함)는 B가 추가한 항목이다. 바꾸면 A에게 알리고 `pnpm run examples:update`로 예시를 다시 만든다.
