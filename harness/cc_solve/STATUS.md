# CC-solve verification campaign — "401개 하나도 빠짐없이 CC로 실제 풀이 점검"

설계상 **CC = Oracle(기준)** 이므로, adapted 401 task 가 진짜 풀리는지 CC 가 *실제로* 풀어 flag/win-condition
이 **동결 정답과 일치**함을 전수 검증한다. 가짜 통과·표본·추정 금지 (cf [[feedback_no_fake_passing]]
[[feedback_no_yamae]]). CC 풀이는 GPU 무관(CC≠로컬 Ollama) — 단 task 가 6v6 에 실제 배포돼야 함.

## 검증 프로토콜 (task 당)
1. **deploy**: 6v6@0.105 에 격리 배포(기존 6v6-* 미영향, 별도 컨테이너/ctfnet). compose up 또는 docker run.
2. **solve**: CC 가 실제 익스/RE/crypto 수행. solver 동봉 시 그것을 *기준*으로 deploy 에 맞춰 재현, 미동봉 시 맨손.
3. **verify**: 획득 flag == frozen_oracle (byte). 일치만 `solved-verified`.
4. **teardown** + 결과 기록(`results.jsonl`).

상태값: `solved-verified` / `failed:<이유>` / `blocked:<이유>`(도구·환경) / `pending`.
**CC 가 못 푼 것 → 설계대로 풀에서 drop** (oracle 미확립 = 무효 task).

## 진행 (resume 시 results.jsonl 이 ground-truth)
| 카테고리 | 대상 | verified | 비고 |
|----------|------|----------|------|
| web      | 78   | **2**    | notmycupofcoffe(Java deser)·gatekeeping(gunicorn SCRIPT_NAME+AES) — 수동배포+익스 |
| rev      | 96   | **6**    | offline solver 작동분(bananascript·gopherz·macomal·checker·1nsayne·free_as_in_freedom) |
| crypto   | 96   | 0        | cybench=subtask-oracle(배포필요), nyu=다음 배치 |
| pwn      | 55   | 0        | static-only(6v6 gdb/pwntools 부재) — 난이도↑ |
| misc     | 34   | 0        | |
| general  | 33   | 0        | intercode picoCTF 다수 |
| forensics| 9    | 0        | pcap 만(tshark) |
| **계**   | **401** | **8**  | offline 러너 1차. 실패 14(원격타깃 연결/py2/pwntools/angr) → 배포 러너 필요 |

## offline 1차 배치 교훈 (실측)
- 순수 오프라인 solver(주어진 암호문/바이너리에 동작)만 offline 검증됨 (rev 20개 중 6개 = 30%).
- 대부분의 실패는 **solver 가 원격 타깃에 연결**하려다 실패(compose:true) → **배포 러너 필요**(타깃 기동 후 solver).
- 기타: py2 print 문법(쉬운 수정), pwntools/angr 의존. → 배포 러너 + solver 적응이 다음 큰 작업.

## 자원 census (계획 ground)
- shipped solver 보유 **210**(nyu 170 + cybench 40) → deploy+solver 재현으로 검증(빠름; 단 endpoint/py2→3/
  pwntools·pycryptodome 의존 적응 필요).
- 맨손 필요 **191**: cve_bench 40(공개 PoC 존재) + intercode 86(picoCTF) + 무solver ~25 + solver적응 실패분.
- nyu web 26/29 프리빌트 `llmctf/` 이미지(dockerhub pull) → 배포 빠름. 5 build 필요.

## 정직한 규모 고지
401 전수 실풀이는 **여러 세션 캠페인**(하드 CSAW finals pwn/crypto 다수 + 실CVE 익스). 매 턴 실측 배치를
쌓고 results.jsonl 에 누적, 가짜 0. 못 푼 건 honestly failed 기록 후 drop.

## resume 방법
`results.jsonl` 의 id 집합과 `adapted/_ledger.tsv`(status=adapted) 차집합 = 남은 대상.
solver 동봉 web/rev/crypto 부터 deploy+solver, 그 뒤 맨손(cve_bench/intercode/무solver).
