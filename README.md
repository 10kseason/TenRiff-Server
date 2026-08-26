# TenRiff Server

TenRiff protocol v5 클라이언트가 접속하는 독립형 C++17 헤드리스 서버입니다. 차트·음원·BGA를
배포하지 않고 참가자가 가진 BMS SHA-256 교집합만 조정합니다. 실시간 멀티 점수는 화면용
claim이며 랭크 DB에는 들어가지 않습니다.

## 1.0 기능

- 단일 방 최대 8명, 순환 선곡 리더, 채팅, 공통곡 교집합, Ready/Launch/Begin 장벽
- heartbeat, handshake/idle timeout, frame/queue/library 크기 제한
- HTTP health/server-info/leaderboard와 주소별 rate limit
- PBKDF2-SHA256 계정 암호, 만료 bearer session, SQLite WAL/migration/audit log
- 승인 BMS catalog와 10분 one-use challenge ID/nonce
- 같은 릴리즈의 `tenriff-replay-verifier`를 별도 프로세스로 30초 안에 재실행
- 서버가 재계산한 점수만 저장하고 HMAC-SHA256 검증 영수증 발급
- `.osu`와 client score claim은 fail-closed로 랭크 등록 제외
- Caddy HTTPS 종단용 Compose 구성과 검증형 DB backup/restore 도구

## 빌드와 테스트

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

실제 TenRiff `PeerSession` protocol 교차 테스트까지 켜려면:

```powershell
cmake -S . -B build-compat -G "Visual Studio 17 2022" -A x64 `
  -DTENRIFF_CLIENT_SOURCE_DIR=C:/path/to/TenRiff
cmake --build build-compat --config Release
ctest --test-dir build-compat -C Release --output-on-failure
```

Linux는 SQLite3와 OpenSSL 개발 패키지가 필요합니다. `Dockerfile`은 필요한 패키지를 고정해
Release 빌드와 CTest를 수행합니다.

## 직접 실행

```powershell
.\build\Release\tenriff-server.exe --bind 0.0.0.0 --port 27300 `
  --api-port 27302 --database data/tenriff.sqlite3 `
  --receipt-secret-file secrets/receipt-secret `
  --verifier ..\build\Release\tenriff-replay-verifier.exe `
  --replay-staging data/replay-staging `
  --approve-chart-file catalog/approved-charts.txt `
  --name "My TenRiff Ranked Server"
```

`catalog/approved-charts.txt`는 `SHA256=로컬 BMS 경로` 형식입니다. `.bms`, `.bme`, `.bml`,
`.pms`만 승인되며 `.osu`는 이 단계에서 거부됩니다. `--records`는 이전 read-only JSONL
snapshot 호환용이며 DB ranked 모드에서는 DB leaderboard가 우선합니다.

## API

- `GET /healthz`
- `GET /v1/server-info`
- `GET /v1/leaderboards/{chart-sha256}?limit=50` (최대 100)
- `POST /v1/accounts/register` — `username`, `password`
- `POST /v1/accounts/login` — `username`, `password`
- `POST /v1/challenges` — Bearer + 승인된 `chart_sha256`
- `POST /v1/replays` — Bearer + `challenge_id`, `challenge_nonce`, `replay_base64`

Replay evidence는 6 MiB로 제한됩니다. replay 자체에도 동일 challenge ID/nonce가 있어야 하며,
verifier는 chart SHA-256·canonical ruleset·모드 seed·입력 trace를 다시 계산합니다.

## HTTPS 배포

1. `.env.example`을 `.env`로 복사하고 실제 도메인을 지정합니다.
2. `secrets/receipt-secret`에 암호학적 난수 32바이트 이상을 저장합니다. 커밋하지 마세요.
3. Linux용 `tenriff-replay-verifier` 번들을 `runtime/`에 두고 실행 권한을 줍니다.
4. BMS를 `catalog/` 아래 읽기 전용으로 두고 정확한 SHA-256 catalog를 작성합니다.
5. `docker compose up -d --build` 후 외부 HTTPS `/healthz`, 계정→챌린지 흐름을 확인합니다.

Compose는 `27302`를 호스트에 공개하지 않고 Caddy만 내부 API에 연결합니다. `27300`은
차트·계정·비밀번호를 전송하지 않는 protocol v5 게임 조정 포트입니다.

DB 백업/복구는 서버를 정지한 상태에서 다음처럼 수행합니다.

```bash
python tools/database_backup.py backup data/tenriff.sqlite3 backups/tenriff.sqlite3
python tools/database_backup.py restore backups/tenriff.sqlite3 data/tenriff.sqlite3
```

복구는 기존 DB의 `pre-restore` rollback 사본을 먼저 만들며, 입력과 출력 모두
`PRAGMA integrity_check`를 통과해야 성공합니다.

라이선스는 [MIT](LICENSE)입니다. 프로토콜은 [docs/PROTOCOL_V5.md](docs/PROTOCOL_V5.md),
신뢰 경계와 운영 조건은 [SECURITY.md](SECURITY.md)를 참고하세요.
