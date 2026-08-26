# Security Policy

## 현재 신뢰 경계

TenRiff Server 0.1은 친구/LAN/직접 주소 방을 위한 코디네이터입니다. protocol v5는 TLS,
계정 인증, 서버 신원 검증을 제공하지 않으며 점수도 서버에서 replay 재실행하지 않습니다.
따라서 현재 결과는 공개 랭킹 증거가 아닙니다.

서버가 받는 데이터는 닉네임, 채팅, 차트 SHA-256 목록, 선택 차트의 기존 64-bit fingerprint,
방 상태와 점수 claim입니다. 차트 원문, 음원, BGA, 로컬 파일 경로는 받지 않습니다.

기본 방어:

- 최대 8명, 64 KiB frame, 250,000개 SHA-256, 128 KiB 연결별 송신 큐
- 5초 handshake timeout, 10초 heartbeat timeout
- 메시지 순서와 player attribution을 서버에서 재검사
- 점수/판정/게이지 wire 범위 검사
- 경기 중 신규 접속 거부

## 취약점 신고

공개 저장소를 만들 때 보안 연락 주소를 이 문서에 추가합니다. 공개 이슈에 개인정보,
공격용 서버 주소, 재현에 필요하지 않은 실제 차트/음원 파일을 올리지 마세요.

## 인터넷 공개 전 필수 항목

- TLS 또는 인증된 암호화 transport
- 연결/IP별 속도 제한과 동시 연결 제한
- 운영자 연락처, 로그 보존 기간, 개인정보 처리 안내
- fuzzing과 장시간 soak test
- replay evidence 서버 재실행 전까지 ranked 기능 fail-closed
