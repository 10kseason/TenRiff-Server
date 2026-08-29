# TenRiff Server

TenRiff protocol v5 클라이언트가 접속하는 독립형 C++17 헤드리스 서버입니다. 차트·음원·BGA를
배포하지 않고 참가자가 가진 BMS SHA-256 교집합만 조정합니다. 실시간 멀티 점수는 화면용
claim이며 랭크 DB에는 들어가지 않습니다.

## 1.1 기능

- 단일 방 최대 8명, 순환 선곡 리더, 공통곡 교집합, Ready/Launch/Begin 장벽
- 계정 인증형 글로벌 채팅, 관리자 역할 표시, 사용자별 전송 제한
- heartbeat, handshake/idle timeout, frame/queue/library 크기 제한
- HTTP health/server-info/leaderboard와 주소별 rate limit
- PBKDF2-HMAC-SHA256 600,000회 계정 해시, 만료 bearer session, SQLite WAL/migration/audit log
- 마운트된 BMS는 가용 catalog로만 계산하고 첫 랭크 요청 때 등록하며 SHA-256 제외 목록을 적용
- 10분 one-use challenge ID/nonce
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

CI와 ARM64 릴리즈의 replay verifier는 안정판 TenRiff 1.6.0 커밋
`410634a97217ff2ad585f80ad7211ea662d65b4c`에 고정되어 있습니다.

Linux는 SQLite3와 OpenSSL 개발 패키지가 필요합니다. `Dockerfile`은 필요한 패키지를 고정해
Release 빌드와 CTest를 수행합니다.

릴리즈의 `TenRiff-Server-windows-arm64.zip`은 Snapdragon Windows용 네이티브 ARM64
서버, replay verifier, ncnn Vulkan 런타임을 함께 제공합니다. 압축을 푼 뒤
`pwsh -File .\tools\test-snapdragon-gpu.ps1`로 Adreno Vulkan 실행을 강제 검증하고,
`pwsh -File .\tools\start-windows-arm64.ps1 -ChartRoot "D:\BMS"`로 실행합니다.
NCNN은 Hexagon NPU가 아니라 Vulkan GPU를 사용하며, 상세 절차는
[`README-SNAPDRAGON.md`](README-SNAPDRAGON.md)에 있습니다.

## 직접 실행

```powershell
.\build\Release\tenriff-server.exe --bind 0.0.0.0 --port 27301 `
  --api-bind 127.0.0.1 --api-port 27302 --database data/tenriff.sqlite3 `
  --receipt-secret-file secrets/receipt-secret `
  --verifier ..\build\Release\tenriff-replay-verifier.exe `
  --replay-staging data/replay-staging `
  --chart-root catalog `
  --exclude-chart-file catalog/excluded-charts.txt `
  --name "My TenRiff Ranked Server"
```

`--chart-root` 아래의 `.bms`, `.bme`, `.bml`, `.pms` 파일은 시작할 때 재귀적으로
SHA-256을 계산해 사용 가능한 카탈로그로만 보관합니다. 랭킹 DB 행은 플레이어가 해당 BMS의
첫 랭크 챌린지를 요청할 때 한 건씩 생성되므로, 인덱싱만으로 수만 개 리더보드가 생기지
않습니다. 미사용 상태로 전체 선등록되어 있던 이전 DB 행도 카탈로그 적용 시 정리됩니다.

관리자는 제외할 SHA-256을 `catalog/excluded-charts.txt`에 한 줄씩 적고 서버를 재시작하면
됩니다. 제외된 차트는 기존 기록을 보존하지만 리더보드 노출, 새 챌린지, 아직 제출되지 않은
챌린지를 즉시 거부합니다. 심볼릭 링크와 `.osu`는 등록하지 않습니다. 이미 만든
`SHA256=path` 목록은 `--catalog-file`로 지연 등록할 수 있고, `--approve-chart`와
`--approve-chart-file`은 즉시 승인하는 호환용 수동 추가 기능으로 남아 있습니다. `--records`는
이전 read-only JSONL snapshot 호환용이며 DB ranked 모드에서는 DB leaderboard가 우선합니다.

## API

- `GET /healthz`
- `GET /v1/server-info`
- `GET /v1/leaderboards/{chart-sha256}?limit=50` (최대 100)
- `POST /v1/accounts/register` — `username`, `password`
- `POST /v1/accounts/login` — `username`, `password`
- `GET /v1/chat/messages?after_id=0&limit=100` — Bearer + 글로벌 채팅 조회
- `POST /v1/chat/messages` — Bearer + `text` 글로벌 채팅 전송
- `POST /v1/challenges` — Bearer + 승인된 `chart_sha256`
- `POST /v1/replays` — Bearer + `challenge_id`, `challenge_nonce`, `replay_base64`

Replay evidence는 6 MiB로 제한됩니다. replay 자체에도 동일 challenge ID/nonce가 있어야 하며,
verifier는 chart SHA-256·canonical ruleset·모드 seed·입력 trace를 다시 계산합니다.

관리자 계정은 비밀번호 파일을 잠깐 마운트한 일회성 명령으로 생성하거나 재설정합니다. 명령이
성공하면 해당 계정의 기존 bearer session은 모두 폐기됩니다.

```powershell
$adminPasswordFile = (Resolve-Path .\secrets\admin-password).Path
docker compose run --rm --no-deps `
  -v "${adminPasswordFile}:/run/secrets/admin-password:ro" server `
  --database /var/lib/tenriff/tenriff.sqlite3 `
  --receipt-secret-file /run/secrets/receipt-secret `
  --provision-admin ryui --admin-password-file /run/secrets/admin-password `
  --provision-only
Remove-Item -LiteralPath $adminPasswordFile
```

## HTTPS 배포

1. `.env.example`을 `.env`로 복사하고 실제 도메인을 지정합니다.
2. `secrets/receipt-secret`에 암호학적 난수 32바이트 이상을 저장합니다. 커밋하지 마세요.
3. 소스 루트에서 아래 명령으로 Linux 검증기 번들을 `runtime/`에 만듭니다. 이 번들은
   클라이언트와 같은 ncnn 20260526 모델을 CPU에서 실행해 NK3 변환 결과를 재현합니다.
   ```powershell
   docker build --file Dockerfile.verifier --target artifact `
     --output type=local,dest=TenRiff-Server/runtime .
   ```
4. `.env`의 `TENRIFF_CHARTS_PATH`를 BMS 폴더로 지정합니다. 제외할 곡만
   `catalog/excluded-charts.txt`에 SHA-256으로 적습니다.
5. Windows에서 `pwsh -File tools/refresh-ranked-catalog.ps1 -ChartRoot $env:TENRIFF_CHARTS_PATH`
   로 실제 BMS 바이트를 해시한 Docker 카탈로그를 갱신합니다. BMS를 추가하거나 제외 목록을
   바꾼 뒤에도 이 명령을 다시 실행합니다.
6. `docker compose up -d --build` 후 외부 HTTPS `/healthz`, 계정→글로벌 채팅→챌린지 흐름을 확인합니다.

Compose는 Windows bind mount의 대규모 디렉터리 열거 지연을 피하도록 생성된 카탈로그를
읽고, 원본 차트 폴더는 verifier용으로 읽기 전용 마운트합니다. `27302`는 호스트의 loopback에만
공개해 이 PC의 게임 클라이언트가 접근할 수 있게 하고, 외부에서는 Caddy HTTPS만 API에
연결합니다. `27301/TCP`는 차트·계정·비밀번호를 전송하지 않는 protocol v5 게임 조정 포트이며,
외부 HTTPS는 호스트의 `27303/TCP+UDP`로 공개됩니다. 따라서 원격 API 주소에는
`https://도메인:27303`을 사용합니다.

### TenRiff 공식 메인 IP

공식 메인 API `https://121.174.18.181:27303`은 `Caddyfile.main`과
Git 제외 경로인 `secrets/main-api-cert.pem`의 전용 leaf 인증서를 사용합니다. 개인키도
`secrets/main-api-key.pem`에만 두고 Git에 포함하지 않습니다. 운영 PC의 무시된
`compose.override.yaml`에서 `Caddyfile.main`, 인증서, 개인키를 Caddy에 읽기 전용으로
마운트합니다. 인증서와 개인키는 소스·Docker context·릴리즈 압축 파일에 포함하지 않습니다.

Windows WinHTTP는 IP 주소 접속에 TLS SNI를 생략할 수 있으므로 `Caddyfile.main`의
`default_sni`를 제거하지 마세요. 공식 클라이언트는 이 leaf 인증서의 DER SHA-256
`29D8F573E13CE892B8E8D485334C18D104925057B084045DE240C6A257BE99BC`를 메인 API에만
고정 검증합니다. 인증서를 교체할 때는 새 핀을 허용하는 클라이언트를 먼저 배포한 뒤 서버
인증서를 전환해야 합니다. 사설 서버는 일반 도메인 인증서 검증을 그대로 사용합니다.

DB 백업/복구는 서버를 정지한 상태에서 다음처럼 수행합니다.

```bash
python tools/database_backup.py backup data/tenriff.sqlite3 backups/tenriff.sqlite3
python tools/database_backup.py restore backups/tenriff.sqlite3 data/tenriff.sqlite3
```

복구는 기존 DB의 `pre-restore` rollback 사본을 먼저 만들며, 입력과 출력 모두
`PRAGMA integrity_check`를 통과해야 성공합니다.

라이선스는 [MIT](LICENSE)입니다. 프로토콜은 [docs/PROTOCOL_V5.md](docs/PROTOCOL_V5.md),
신뢰 경계와 운영 조건은 [SECURITY.md](SECURITY.md)를 참고하세요.
