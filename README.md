# TenRiff Server

TenRiff의 protocol v5 직접-IP 멀티플레이 클라이언트가 그대로 접속할 수 있는 독립형
헤드리스 코디네이터입니다. 서버는 차트, 음원, BGA 파일을 업로드받거나 배포하지 않습니다.
참가자가 보유한 BMS 차트의 SHA-256 목록에서 교집합만 계산하고 방 상태와 경기 시작 장벽을
중계합니다.

현재 `0.1.0`은 첫 서버 기반입니다.

- 단일 방, 최대 8명
- 첫 접속자가 첫 선곡 리더이며 매 라운드 완료 후 순환
- `Hello`, 방 roster, 채팅, 공통곡 SHA-256 교집합
- 차트 선택, Ready, Launch/Loaded/Begin 장벽
- 실시간/최종 점수 claim 중계와 라운드 reset
- heartbeat, handshake/idle timeout, 프레임/큐/라이브러리 크기 제한
- Windows와 Linux용 무의존 C++17 빌드

> 현재 점수는 protocol v5의 **검증되지 않은 claim**입니다. 이 서버는 공개 랭킹 서버가
> 아니며, replay 재실행 검증과 서명된 기록 영수증은 후속 단계입니다.

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
.\build\Release\tenriff-server.exe --bind 0.0.0.0 --port 27300 --name "My TenRiff Room"
```

TenRiff에서 `JOIN`을 선택하고 서버 주소와 포트를 입력합니다. 첫 번째 접속자가 방의 첫
선곡 리더가 됩니다. 서버 종료은 `Ctrl+C`입니다.

사용 가능한 인자:

- `--bind <IPv4>`: 수신 주소, 기본 `0.0.0.0`
- `--port <1..65535>`: TCP 포트, 기본 `27300`
- `--name <text>`: handshake에 표시할 서버 이름, 최대 64 UTF-8 바이트
- `--help`: 도움말

인터넷에 공개할 때는 운영체제 방화벽과 공유기 포트 포워딩에서 같은 TCP 포트를 열어야
합니다. protocol v5 자체에는 암호화와 계정 인증이 없으므로 신뢰할 수 없는 인터넷에 바로
노출하는 운영은 아직 권장하지 않습니다.

## 저장소 경계

이 디렉터리는 TenRiff 클라이언트와 별개의 저장소로 게시하기 위한 독립 프로젝트입니다.
클라이언트의 BMS 파서, 그래픽, 오디오, 스킨과 모델 파일을 의존하지 않습니다. 공개 전에는
프로젝트 라이선스(MIT 또는 AGPL-3.0 계열)와 운영 정책을 확정해야 합니다.

- 프로토콜: [`docs/PROTOCOL_V5.md`](docs/PROTOCOL_V5.md)
- 보안/운영 경계: [`SECURITY.md`](SECURITY.md)
- 다음 구현 단계: [`docs/ROADMAP.md`](docs/ROADMAP.md)
