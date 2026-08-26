# TenRiff peer protocol v5 서버 호환 규격

이 서버는 TenRiff 클라이언트의 기존 직접-IP protocol v5 wire format을 구현합니다.

## Frame

모든 정수는 big-endian입니다.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `TRP1` (`0x54525031`) |
| 4 | 2 | protocol version `5` |
| 6 | 2 | message type |
| 8 | 4 | payload bytes |
| 12 | N | payload |

최대 payload는 64 KiB입니다. 문자열은 `u16 byte_length + UTF-8 bytes`, SHA-256은 32 raw
bytes로 전달됩니다.

## Headless handshake

1. TCP 연결 직후 서버가 `Hello(server_name)`을 보냅니다.
2. 클라이언트가 `Hello(player_name)`을 보냅니다.
3. 서버가 `RoomWelcome(player_id, leader_id)`와 `RoomRoster`를 보냅니다.
4. 클라이언트가 `LibraryBegin`, 0개 이상의 `LibraryChunk`, `LibraryEnd`를 보냅니다.
5. 모든 참가자의 목록이 완성되면 서버가 각 참가자에게 `CommonLibraryBegin/Chunk/End`를
   보냅니다.

헤드리스 서버 자체는 플레이어 슬롯을 차지하지 않습니다. 첫 접속자는 player 1과 첫 리더를
받고 최대 8명의 실제 클라이언트가 접속할 수 있습니다.

## 방 상태 권위

서버는 수신 frame의 `player_id`를 신뢰하지 않고 TCP 연결에 할당한 ID로 덮어씁니다.

- 리더만 새 차트를 선택하고 `Launch`/`Begin`할 수 있습니다.
- 다른 참가자의 차트 fingerprint/size는 리더 선택과 정확히 일치해야 합니다.
- 모든 참가자가 같은 차트를 확인하고 Ready여야 Launch가 통과합니다.
- 모든 참가자가 Loaded여야 Begin이 통과합니다.
- Score/FinalScore/RoundReset은 활성 round nonce와 일치해야 합니다.
- 전원이 final score 후 reset하면 다음 접속 순서 참가자로 리더가 순환합니다.

## 콘텐츠 경계

`LibraryChunk`에는 차트 SHA-256만 있습니다. 차트 경로, 제목, BMS 원문, keysound, BGA는
이 프로토콜로 전송하지 않습니다. `Chart`의 제목은 사용자가 선택한 표시 문자열이며 콘텐츠
다운로드 식별자나 파일 전송 기능이 아닙니다.

## 무결성 한계

protocol v5의 64-bit chart fingerprint는 기존 방의 exact-byte 일치용이며 암호학적 랭킹
식별자가 아닙니다. 점수 packet의 범위와 순서는 검사하지만 replay proof가 없어 플레이 실적을
증명하지 않습니다. 공개 랭킹은 별도 versioned API와 SHA-256 catalog, replay 재실행 검증을
사용해야 합니다.
