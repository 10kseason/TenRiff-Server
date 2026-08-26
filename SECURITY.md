# Security Policy

## 신뢰 경계

protocol v5 실시간 점수는 비신뢰 화면 데이터이며 랭크 DB에 기록하지 않습니다. 랭크 등록은
HTTPS 계정 API가 발급한 10분 one-use challenge, 승인 BMS SHA-256, replay 파일 안의 동일
challenge ID/nonce, 서버 외부 프로세스의 canonical replay 재실행을 모두 통과해야 합니다.
`.osu`와 client score claim은 fail-closed입니다.

계정 비밀번호는 16바이트 random salt와 PBKDF2-HMAC-SHA256 210,000회 결과만 저장합니다.
Bearer 원문은 DB에 저장하지 않고 SHA-256 digest와 24시간 만료만 둡니다. 검증 영수증은
운영자 secret의 HMAC-SHA256이며 secret은 파일/컨테이너 secret으로만 주입합니다.

기본 방어:

- 게임 최대 8명, 64 KiB frame, 250,000 SHA-256, 연결별 128 KiB 송신 큐
- 5초 handshake, 10초 heartbeat, 메시지 순서/player attribution/wire 범위 검사
- HTTP 8 MiB, replay 6 MiB, 연결 32개, 5초 timeout, 주소별 분당 제한
- verifier 30초 timeout, stdout 64 KiB 제한, shell을 거치지 않는 argv 실행
- SQLite foreign key/WAL/transaction, migration table, audit log, one-use challenge transaction
- HTTPS Caddy 뒤의 내부 API, read-only container root, capability drop, no-new-privileges

멀티플레이 `27300` 자체는 TLS가 아니므로 계정 token, 비밀번호, replay를 보내지 않습니다.
민감 데이터는 HTTPS API에서만 처리합니다. API 내부 포트 `27302`는 인터넷에 직접 publish하지
마세요.

## 운영

- receipt secret과 DB backup은 서로 다른 접근 권한으로 보관합니다.
- 승인 catalog의 SHA-256과 실제 마운트 파일을 배포 전에 verifier로 확인합니다.
- DB backup/restore 후 `PRAGMA integrity_check`와 계정→챌린지→검증 smoke를 수행합니다.
- secret 유출 시 새 key version으로 교체하고 기존 receipt 신뢰 기간을 운영 공지합니다.
- 로그에는 bearer token, 비밀번호, replay 원문을 남기지 않습니다.

## 취약점 신고

GitHub Security Advisory의 비공개 신고 기능을 사용하세요. 공개 이슈에 개인정보, token,
실제 운영 DB, 공격용 서버 주소, 재현에 필요하지 않은 차트·음원을 올리지 마세요.
