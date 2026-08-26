# TenRiff Server

TenRiff의 protocol v5 직접-IP 멀티플레이 클라이언트가 그대로 접속할 수 있는 독립형
헤드리스 코디네이터입니다. 서버는 차트, 음원, BGA 파일을 업로드받거나 배포하지 않습니다.
참가자가 보유한 BMS 차트의 SHA-256 목록에서 교집합만 계산하고 방 상태와 경기 시작 장벽을
중계합니다.

현재 `0.2.0-dev`는 첫 서버 기반과 읽기 전용 온라인 기록 API를 포함합니다.

- 단일 방, 최대 8명
- 첫 접속자가 첫 선곡 리더이며 매 라운드 완료 후 순환
- `Hello`, 방 roster, 채팅, 공통곡 SHA-256 교집합
- 차트 선택, Ready, Launch/Loaded/Begin 장벽
- 실시간/최종 점수 claim 중계와 라운드 reset
- heartbeat, handshake/idle timeout, 프레임/큐/라이브러리 크기 제한
- Windows와 Linux용 무의존 C++17 빌드
- 별도 `27302/TCP` HTTP API의 health/server-info/차트별 leaderboard 조회
- 운영자가 제공한 JSONL 중 `bms + online_verified`만 노출하고 `.osu`와 client claim은 제외

> protocol v5 경기 점수는 여전히 **검증되지 않은 claim**입니다. 기록 API의
> `online_verified` 스냅샷은 서버 외부 검증 파이프라인이 만든 입력만 읽으며, 이 서버 자체는
> 아직 replay를 재실행하거나 기록을 승인하지 않습니다. 따라서 현재 빌드는 공개 랭킹 서버가
> 아닙니다.

## 빌드

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

TenRiff 클라이언트 checkout과 실제 `PeerSession` 교차 테스트까지 켜려면 다음처럼 경로를
지정합니다. 이 옵션은 서버 단독 빌드에는 필요하지 않습니다.

```powershell
cmake -S . -B build-compat -G "Visual Studio 17 2022" -A x64 `
  -DTENRIFF_CLIENT_SOURCE_DIR=C:/path/to/TenRiff
cmake --build build-compat --config Release
ctest --test-dir build-compat -C Release --output-on-failure
```

Linux에서는 다음처럼 빌드합니다.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## 실행

```powershell
.\build\Release\tenriff-server.exe --bind 0.0.0.0 --port 27300 `
  --api-port 27302 --records data/records.example.jsonl --name "My TenRiff Room"
```

TenRiff에서 `JOIN`을 선택하고 서버 주소와 포트를 입력합니다. 첫 번째 접속자가 방의 첫
선곡 리더가 됩니다. 서버 종료은 `Ctrl+C`입니다.

사용 가능한 인자:

- `--bind <IPv4>`: 수신 주소, 기본 `0.0.0.0`
- `--port <1..65535>`: TCP 포트, 기본 `27300`
- `--api-port <1..65535>`: 읽기 전용 기록 HTTP 포트, 기본 `27302`
- `--records <path>`: 서버 검증 파이프라인이 만든 JSONL 스냅샷; 생략하면 빈 리더보드
- `--name <text>`: handshake에 표시할 서버 이름, 최대 64 UTF-8 바이트
- `--help`: 도움말

기록 API:

- `GET /healthz`
- `GET /v1/server-info`
- `GET /v1/leaderboards/{64자리-chart-sha256}?limit=50` (`limit` 최대 100)

한 줄에 평평한 JSON object 하나를 쓰는 JSONL 형식이며 필수 필드는
`chart_sha256`, `chart_format`, `player_name`, `score`, `accuracy`, `max_combo`,
`clear_status`, `ruleset_id`, `verification_status`, `verified_at_utc`입니다.
`chart_format`이 정확히 `bms`이고 `verification_status`가 `online_verified`인 항목만
읽습니다. 예시는 [`data/records.example.jsonl`](data/records.example.jsonl)에 있습니다.

현재 HTTP API와 protocol v5에는 TLS/계정 인증이 없습니다. 인터넷 공개 시에는 역방향
프록시에서 HTTPS를 종단하고 게임 포트와 API 포트에 rate limit을 적용하기 전까지 운영하지
마세요.

## 저장소 경계

이 디렉터리는 TenRiff 클라이언트와 별개의 저장소로 게시하기 위한 독립 프로젝트입니다.
클라이언트의 BMS 파서, 그래픽, 오디오, 스킨과 모델 파일을 의존하지 않습니다. 공개 전에는
프로젝트 라이선스(MIT 또는 AGPL-3.0 계열)와 운영 정책을 확정해야 합니다.

- 프로토콜: [`docs/PROTOCOL_V5.md`](docs/PROTOCOL_V5.md)
- 보안/운영 경계: [`SECURITY.md`](SECURITY.md)
- 다음 구현 단계: [`docs/ROADMAP.md`](docs/ROADMAP.md)
