# Canary 사용법

Canary는 외부 수신자별 데이터 사본에 서로 다른 합성 문항을 추가하고, 나중에 발견된 파일에서 표식을 검색하는 CLI 시제품이다. 원본 파일은 수정하지 않는다. 데이터를 암호화하거나 다시 가져올 때 복원하는 기능은 아니다.

## 현재 지원 범위

발급 입력은 한 줄에 객관식 문항 하나가 들어 있는 UTF-8 JSONL이다. 필드는 아래 네 가지이며 정답은 선택지 중 하나와 같아야 한다.

```json
{"id":"q1","question":"부품 20개 중 3개를 출고하면 몇 개가 남습니까?","choices":["17","20","23"],"answer":"17"}
```

CSV, 엑셀, 상담 기록, PDF 및 임의 JSON 스키마는 지원하지 않는다. 기본 생성기는 영어 물류·재고 문제를 추가하므로 다른 언어·분야의 데이터에 자연스럽게 섞인다는 보장은 없다. 선택적 LLM 생성도 생성 문항의 업무 적합성 검토를 대신하지 않는다. 고객용 업로드 화면과 자동 파일 전송은 없다.

## 샘플 실행

저장소 루트에서 다음을 실행한다. 출력 폴더가 이미 있으면 다른 경로를 지정한다.

```bash
bash demo/canary-demo.sh out/canary-demo
```

샘플 40문항에 업체별 문항 5개를 추가하고, vendorB 사본 일부의 유출을 식별한다. 이후 모의 모델 질의·견고성 실험을 실행하고 `out/canary-demo/report.md`를 생성한다. 모의 모델 결과는 실제 모델 탐지 성능의 검증이 아니다. 데모가 사용하는 공개 가짜 키는 실제 발급에 사용하지 않는다.

## 직접 발급하고 검사하기

```bash
# 실제 발급용 키: 안전하게 별도 보관한다.
export ARGOS_CANARY_KEY="$(openssl rand -hex 32)"

pnpm argos canary issue \
  --input src/canary/fixtures/eval.jsonl \
  --recipients companyA,companyB \
  --out out/issued

# companyA.jsonl과 companyB.jsonl을 각각 해당 업체에 전달한다.
# registry.json과 llm-usage.json은 내부에 보관한다.

# companyB 사본을 유출 의심 파일로 사용한 실행 예시
pnpm argos canary scan out/issued/companyB.jsonl \
  --registry out/issued/registry.json \
  --json out/issued/scan.json

pnpm argos canary report \
  --registry out/issued/registry.json \
  --scan out/issued/scan.json \
  --out out/issued/report.md
```

각 수신자 사본은 원본 문항 전부와 새 합성 문항을 포함한다. 레지스트리에 표식과 수신자의 대응 관계를 저장하며 파일 권한은 600이다. 기존 출력 폴더와 결과 파일은 덮어쓰지 않는다. 발급에는 키가 필요하고 검색·보고서에는 레지스트리만 있으면 된다. 키를 함께 제공한 경우 레지스트리와 일치해야 한다.

검색의 종료 코드는 미식별 0, 식별 또는 혼합 출처 1, 실행 오류 2다. 따라서 검색에서 1이 반환되는 것은 탐지 성공을 뜻한다. `set -e` 스크립트에서는 이 코드를 별도로 처리해야 보고서 생성까지 진행한다.

## 결과 해석

- `IDENTIFIED`: 한 수신자 사본의 표식이 발견됨. 그 수신자가 직접 유출했다는 증명은 아니다.
- `MIXED_SOURCES`: 여러 수신자의 표식이 발견됨. 하나의 수신자로 단정하지 않는다.
- `UNIDENTIFIED`: 표식을 찾지 못함. 표식 없는 일부만 유출되거나 표식이 삭제되면 추적할 수 없다.

실제 고객을 가정한 CLI 점검에서 원본 유지, 업체별 사본 발급, 일부 유출 식별, 혼합 출처 표시, 보고서 생성과 토큰 비노출, 덮어쓰기 거부를 확인했다. CSV 발급은 지원하지 않아 거부되는 것도 확인했다.

```bash
pnpm run typecheck
node --import tsx --test --test-timeout=60000 test/canary.test.ts
```
