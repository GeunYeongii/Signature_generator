# Snort Rule Signature Generator

## 개요
Snort 규칙을 기반으로 네트워크 패킷을 생성하고 전송해 보안 장비의 탐지 능력을 테스트하는 도구다. Snort 규칙 파일을 파싱해 해당 규칙에 매칭되는 네트워크 패킷을 생성하고, 이를 네트워크로 전송하거나 PCAP 파일로 저장할 수 있다.

## 주요 기능
- Snort 규칙 파싱 및 분석
- 규칙 기반 네트워크 패킷 생성  
  `alert tcp any any -> any 25 (msg:"win32/netsky.worm.29568-1"; flow:to_server; content:"|0d 0a 0d 0a|"; content:"AADgAADAAAAAAHRhAAAAcAAAALAAAHRvAAAABAAAAAAAAAAAAAAAAAAA4AAAwAAAAABhAAAA"; distance:515; within:72; classtype:low-rarity; sid:5;)`

    
  ![image](https://github.com/user-attachments/assets/dc5ffaeb-52f2-4f8c-bc0d-0c7c9d53a175)
  ![image](https://github.com/user-attachments/assets/791f8ce1-8da7-42d2-a212-85a938d691e6)

- 생성된 패킷의 PCAP 파일 저장
- 네트워크를 통한 패킷 전송
- 패킷 전송 결과 분석 및 시각화
- 상세한 로깅 및 통계 제공

## 프로젝트 구조
```
snort-rule-signature-generator/
├── main.py              # 메인 실행 파일
├── rule_parser.py       # Snort 규칙 파싱 모듈
├── packet_generator.py  # 패킷 생성 모듈
├── output_handler.py    # 출력 및 로깅 처리 모듈
├── requirements.txt     # 필요한 패키지 목록
└── logs/                # 로그 파일 디렉토리
```

## 아키텍처

### 1. RuleParser (rule_parser.py)
Snort 규칙 파일을 파싱해 규칙의 구성 요소를 추출한다.
- 헤더 정보 (프로토콜, 출발지/목적지 IP, 포트)
- 옵션 정보 (content, pcre, depth, distance 등)
- 메타데이터 (sid, msg, reference 등)

### 2. PacketGenerator (packet_generator.py)
파싱된 규칙 정보를 기반으로 Scapy를 사용해 네트워크 패킷을 생성한다.
- TCP, UDP, ICMP 프로토콜 지원
- content, pcre 등의 페이로드 생성
- depth, distance, within, offset 등의 위치 옵션 처리
- HTTP 요청 형식 패킷 생성

### 3. OutputHandler (output_handler.py)
생성된 패킷을 처리하고 결과를 관리한다.
- PCAP 파일 저장 기능
- 네트워크 패킷 전송 기능
- 응답 분석 및 통계 생성
- 로깅 및 결과 시각화

### 4. Main (main.py)
사용자 인터페이스와 전체 워크플로우를 관리한다.
- 명령줄 인터페이스 제공
- 모듈 간 데이터 흐름 조정
- 오류 처리 및 사용자 피드백

## 데이터 흐름
1. 사용자가 Snort 규칙 파일과 옵션을 지정해 프로그램 실행
2. RuleParser가 규칙 파일을 파싱해 구조화된 규칙 정보 생성
3. PacketGenerator가 파싱된 규칙을 기반으로 패킷 생성
4. OutputHandler가 생성된 패킷을 PCAP 파일로 저장하거나 네트워크로 전송
5. 패킷 전송 결과를 분석하고 통계 및 시각화 제공

## 사용 방법

### 기본 사용법
```bash
python main.py -r rules.txt -d 192.168.1.100
```

### 명령줄 옵션
- `-r, --rules`: Snort 규칙 파일 경로 (필수)
- `-d, --dst-ip`: 대상 IP 주소 (기본값: 192.168.1.2)
- `-s, --src-ip`: 출발지 IP 주소 (기본값: 로컬 IP)
- `-o, --output`: PCAP 파일 저장 경로 (선택 사항)
- `-i, --interval`: 패킷 전송 간격(초) (기본값: 0.1)
- `--no-responses`: PCAP 파일에 응답 패킷을 포함하지 않음 (기본값: 응답 포함)

## 결과 해석
패킷 전송 후 다음과 같은 결과 카테고리가 표시된다:

- **Success**: 패킷이 성공적으로 전송되고 응답을 받음
- **Rejected**: 연결이 명시적으로 거부됨 (TCP RST 또는 ICMP Unreachable)
- **Blocked**: 패킷이 차단되었거나 응답이 없음 (TCP의 경우)
- **Timeout**: 응답이 없음 (UDP, ICMP의 경우)
- **Error**: 패킷 전송 중 오류 발생

## 로깅
모든 활동은 `logs` 디렉토리에 날짜별로 로그 파일에 기록된다. 로그 파일에는 패킷 전송 정보, 응답 결과, 오류 메시지 등이 포함된다.

## 주의 사항
- 이 도구는 보안 테스트 목적으로만 사용해야 한다.
- 권한이 있는 네트워크에서만 사용하라.
- 일부 패킷은 방화벽이나 IPS에 의해 차단될 수 있다.
- 관리자 권한(sudo/administrator)으로 실행해야 할 수 있다. 
