# 서버 단계 계획

## 0.1 — 헤드리스 코디네이터 (완료)

- 기존 TenRiff protocol v5 join 클라이언트 호환
- 단일 방, 직접 `host:port` 접속
- 콘텐츠 파일을 받지 않는 SHA-256 교집합 방식
- 결정적 coordinator 단위 테스트와 TCP handshake smoke test

## 0.2 — 운영 가능한 개인 서버

- TOML/JSON 설정 파일과 graceful restart
- 연결/IP rate limit, deny list, room password의 안전한 PAKE 또는 TLS 기반 처리
- 여러 방과 방 코드
- Docker 이미지와 Windows 서비스/Linux systemd 예시
- protocol golden vector를 클라이언트 CI에서도 교차 검증

## 0.3 — 읽기 전용 온라인 기록 (개발 기반 완료, 공개 운영 미완료)

- 완료: 별도 schema-v1 HTTP API, health/server-info/leaderboard 조회
- 완료: `bms + online_verified` JSONL만 읽고 `.osu`/client claim fail-closed
- 남음: 승인된 BMS SHA-256 catalog와 스냅샷 서명/검증 파이프라인
- 남음: HTTPS reverse proxy, rate limit, 운영 배포와 관측성

## 0.4 — shadow replay 검증

- one-time challenge, idempotency key, replay SHA-256
- 서버에 등록된 BMS 차트와 동일한 headless 규칙 엔진으로 replay v3 재실행
- 공개 순위에는 미반영하고 불일치/비용/오탐을 측정
- append-only 검증 감사 로그

## 1.0 — 검증된 공개 랭킹

- 계정/복구/개인정보 정책
- `online_verified` 결과만 공개
- ruleset/시즌 분리와 서버 서명 영수증
- 이의 제기와 재검증 경로

게임 자산 업로드, 자동 다운로드, BMS/BGA/음원 호스팅은 이 로드맵에 포함하지 않습니다.
