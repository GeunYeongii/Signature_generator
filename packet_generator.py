from typing import Dict, List, Any, Optional, Tuple
from scapy.all import IP, TCP, UDP, ICMP, Raw
from scapy.packet import Packet
import random
import re
import socket
import ipaddress
import string

class PacketGenerator:
    """Snort 룰 정보를 기반으로 패킷을 생성하는 클래스"""
    
    def __init__(self):
        self.supported_protocols = ['tcp', 'udp', 'icmp']
    
    def generate_packets(self, parsed_rules: List[Dict[str, Any]], dst_ip: str = None, src_ip: str = None) -> List[Tuple[Dict[str, Any], Packet]]:
        """여러 룰에 대한 패킷 생성"""
        packets = []
        
        for rule in parsed_rules:
            try:
                packet = self.generate_packet(rule, dst_ip, src_ip)
                if packet:
                    packets.append((rule, packet))
            except Exception as e:
                print(f"Packet generation error (SID: {rule.get('sid', 'unknown')}): {str(e)}")
        
        return packets
    
    def generate_packet(self, rule: Dict[str, Any], dst_ip: str = None, src_ip: str = None) -> Optional[Packet]:
        """단일 룰에 대한 패킷 생성"""
        try:
            protocol = rule['protocol']
            
            if protocol not in self.supported_protocols:
                print(f"Unsupported protocol: {protocol} (SID: {rule.get('sid', 'unknown')})")
                return None
            
            # 명령줄에서 지정한 IP 사용
            if dst_ip is None:
                dst_ip = "192.168.1.2"  # 기본 목적지 IP
            
            if src_ip is None:
                # 로컬 IP 사용
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    src_ip = s.getsockname()[0]
                    s.close()
                except:
                    src_ip = "192.168.1.1"  # 기본 출발지 IP
            
            print(f"Generating packet (SID: {rule.get('sid', 'unknown')})")
            print(f"  - Protocol: {protocol.upper()}")
            print(f"  - Source IP: {src_ip}")
            print(f"  - Destination IP: {dst_ip}")
            
            # 포트 정보 처리 - Snort 규칙의 포트 정보는 유지
            src_port = self._get_port(rule['src_port'])
            dst_port = self._get_port(rule['dst_port'])
            
            print(f"  - Ports: {src_port} -> {dst_port}")
            
            ip_layer = IP(src=src_ip, dst=dst_ip)
            
            # 프로토콜 레이어 생성
            if protocol == 'tcp':
                proto_layer = TCP(sport=src_port, dport=dst_port, flags="S")
                
                # TCP 플래그 옵션 처리
                if 'flags' in rule.get('options', {}):
                    flags_str = rule['options']['flags']
                    tcp_flags = self._parse_tcp_flags(flags_str)
                    proto_layer.flags = tcp_flags
            elif protocol == 'udp':
                proto_layer = UDP(sport=src_port, dport=dst_port)
            elif protocol == 'icmp':
                proto_layer = ICMP(type=8, code=0)  # Echo Request
                
                # ICMP 타입/코드 옵션 처리
                if 'itype' in rule.get('options', {}):
                    try:
                        proto_layer.type = int(rule['options']['itype'])
                    except ValueError:
                        pass
                
                if 'icode' in rule.get('options', {}):
                    try:
                        proto_layer.code = int(rule['options']['icode'])
                    except ValueError:
                        pass
            
            # 페이로드 생성
            payload = self._generate_payload(rule)
            
            # 패킷 조립
            packet = ip_layer / proto_layer / Raw(load=payload)
            
            return packet
        except Exception as e:
            print(f"Error generating packet (SID: {rule.get('sid', 'unknown')}): {str(e)}")
            return None
    
    def _parse_tcp_flags(self, flags_str: str) -> int:
        """TCP 플래그 문자열을 플래그 값으로 변환"""
        flag_map = {
            'F': 0x01,  # FIN
            'S': 0x02,  # SYN
            'R': 0x04,  # RST
            'P': 0x08,  # PSH
            'A': 0x10,  # ACK
            'U': 0x20,  # URG
            'E': 0x40,  # ECE
            'C': 0x80   # CWR
        }
        
        flags = 0
        for char in flags_str.upper():
            if char in flag_map:
                flags |= flag_map[char]
        
        return flags
    
    def _get_ip_from_cidr(self, cidr: str) -> str:
        """CIDR 표기법에서 IP 주소 추출"""
        try:
            # CIDR 표기법이 아닌 경우 그대로 반환
            if '/' not in cidr:
                return cidr
            
            # 'any' 키워드 처리
            if cidr.lower() == 'any' or cidr == '0.0.0.0/0':
                return '192.168.1.1'  # 기본 IP 반환
            
            # ipaddress 모듈을 사용하여 네트워크에서 IP 주소 추출
            network = ipaddress.ip_network(cidr, strict=False)
            
            # 네트워크 주소가 아닌 첫 번째 호스트 주소 반환
            for host in network.hosts():
                return str(host)
            
            # 호스트가 없는 경우 네트워크 주소 반환
            return str(network.network_address)
        except Exception as e:
            print(f"Error extracting IP from CIDR {cidr}: {str(e)}")
            return '192.168.1.1'  # 오류 발생 시 기본 IP 반환
    
    def _get_port(self, port_info) -> int:
        """포트 정보에서 포트 번호 추출"""
        # 포트 범위 처리
        if isinstance(port_info, dict):
            start = port_info.get('start', 1024)
            end = port_info.get('end', 65535)
            return random.randint(start, end)
        elif isinstance(port_info, list):  # 포트 목록
            if port_info:
                return random.choice(port_info)
            else:
                return random.randint(1024, 65535)
        
        # 문자열인 경우 숫자로 변환 시도
        if isinstance(port_info, str):
            try:
                return int(port_info)
            except ValueError:
                # 변환할 수 없는 경우 기본 포트 반환
                return random.randint(1024, 65535)
                
        return port_info
    
    def _generate_payload(self, rule: Dict[str, Any]) -> bytes:
        """룰 정보를 기반으로 패킷 페이로드 생성"""
        # 특정 취약점 SID 또는 메시지 기반 특수 처리
        sid = rule.get('sid', '')
        msg = rule.get('msg', '')
        
        # Adobe ColdFusion 취약점 (CVE-2024-53961)
        if "Adobe ColdFusion" in msg and "Directory Traversal" in msg:
            return b"GET /pms?module=logging&file_name=../../../etc/passwd HTTP/1.1\r\nHost: target\r\nConnection: keep-alive\r\n\r\n"
        
        # content 옵션 처리
        if rule.get('content'):
            # HTTP 요청 감지
            is_http = False
            for content in rule['content']:
                if 'GET' in content or 'POST' in content or 'HTTP' in content:
                    is_http = True
                    break
            
            if is_http:
                return self._generate_http_payload(rule)
            else:
                return self._generate_content_payload(rule)
        
        # pcre 옵션 처리
        elif rule.get('pcre'):
            return self._generate_pcre_payload(rule['pcre'])
        
        # 기본 페이로드
        # 규칙 메시지를 기반으로 페이로드 생성
        if rule.get('msg'):
            return f"PAYLOAD_FOR_{rule.get('msg', '')}".encode()
        else:
            return f"DEFAULT_PAYLOAD_FOR_SID_{rule.get('sid', '0')}".encode()
    
    def _generate_http_payload(self, rule: Dict[str, Any]) -> bytes:
        """HTTP 요청 형식의 페이로드 생성"""
        method = b"GET"
        path = b"/"
        http_version = b"HTTP/1.1"
        headers = {
            b"Host": b"target",
            b"User-Agent": b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            b"Accept": b"*/*",
            b"Connection": b"keep-alive"
        }
        body = b""
        
        # 특정 취약점 처리
        sid = rule.get('sid', '')
        msg = rule.get('msg', '')
        
        # Nginx Unit Router 힙 기반 버퍼 오버플로우 취약점 (SID: 6820)
        if "Nginx Unit Router Process Heap-based Buffer Overflow" in msg or sid == "6820":
            # 비정상적으로 큰 Content-Length 값 설정
            headers[b"Content-Length"] = b"2147483650"  # 214,748,364 이상의 값
            method = b"POST"
            path = b"/api/1/config"
            body = b"A" * 1024  # 실제 본문 크기는 중요하지 않음 (Content-Length 값이 중요)
            return self._build_http_request(method, path, http_version, headers, body)
        
        # 일반적인 HTTP 요청 생성 로직
        content_options = []
        http_header_options = []
        
        # content 옵션 분석
        for i, content in enumerate(rule.get('content', [])):
            content_bytes = self._process_content_string(content)
            content_options.append((content, content_bytes))
            
            # HTTP 헤더 옵션 확인
            if rule.get('options', {}).get(f'http_header:{i}') or rule.get('options', {}).get('http_header'):
                http_header_options.append((content, content_bytes))
        
        # HTTP 메서드 감지
        for content, content_bytes in content_options:
            if content_bytes.startswith(b"GET"):
                method = b"GET"
                break
            elif content_bytes.startswith(b"POST"):
                method = b"POST"
                break
            elif content_bytes.startswith(b"PUT"):
                method = b"PUT"
                break
            elif content_bytes.startswith(b"DELETE"):
                method = b"DELETE"
                break
        
        # 경로 감지
        for content, content_bytes in content_options:
            if content_bytes.startswith(b"/"):
                path = content_bytes
                break
        
        # HTTP 헤더 처리
        for content, content_bytes in http_header_options:
            if b":" in content_bytes:
                header_parts = content_bytes.split(b":", 1)
                if len(header_parts) == 2:
                    header_name = header_parts[0].strip()
                    header_value = header_parts[1].strip()
                    headers[header_name] = header_value
        
        # 특정 헤더 처리
        for content, content_bytes in content_options:
            # Content-Length 헤더 처리
            if b"Content-Length" in content_bytes:
                # byte_test 옵션 확인
                byte_test_options = [opt for opt in rule.get('options', {}).keys() if opt.startswith('byte_test')]
                if byte_test_options:
                    # 비정상적으로 큰 Content-Length 값 설정
                    headers[b"Content-Length"] = b"2147483650"
                    # POST 요청으로 변경
                    method = b"POST"
                    # 본문 추가
                    body = b"A" * 1024
        
        return self._build_http_request(method, path, http_version, headers, body)
    
    def _build_http_request(self, method: bytes, path: bytes, http_version: bytes, headers: Dict[bytes, bytes], body: bytes) -> bytes:
        """HTTP 요청 메시지 구성"""
        # 요청 라인
        request = method + b" " + path + b" " + http_version + b"\r\n"
        
        # 헤더 추가
        for name, value in headers.items():
            request += name + b": " + value + b"\r\n"
        
        # 헤더와 본문 구분
        request += b"\r\n"
        
        # 본문 추가 (있는 경우)
        if body:
            request += body
        
        return request
    
    def _generate_content_payload(self, rule: Dict[str, Any]) -> bytes:
        """content 옵션을 기반으로 페이로드 생성 (depth, distance 등 고려)"""
        # HTTP 관련 옵션 확인
        options = rule.get('options', {})
        http_options = [opt for opt in options.keys() if opt.startswith('http_')]
        
        # HTTP 관련 옵션이 있으면 HTTP 페이로드 생성
        if http_options:
            return self._generate_http_payload(rule)
        
        # 일반 페이로드 생성 로직
        result = bytearray()
        last_end = 0
        
        contents = rule.get('content', [])
        
        for i, content in enumerate(contents):
            content_bytes = self._process_content_string(content)
            
            # 현재 content에 대한 옵션 찾기
            depth_key = f"depth:{i}" if f"depth:{i}" in options else "depth"
            distance_key = f"distance:{i}" if f"distance:{i}" in options else "distance"
            within_key = f"within:{i}" if f"within:{i}" in options else "within"
            offset_key = f"offset:{i}" if f"offset:{i}" in options else "offset"
            
            # offset 처리 (절대 위치)
            if offset_key in options:
                try:
                    offset = int(options[offset_key])
                    # 현재 결과 길이가 offset보다 작으면 랜덤 데이터로 채움
                    if len(result) < offset:
                        padding = self._generate_random_bytes(offset - len(result))
                        result.extend(padding)
                    else:
                        # 이미 offset 위치를 지났으면 결과를 offset 위치까지 자름
                        result = result[:offset]
                    
                    # content 추가
                    result.extend(content_bytes)
                    last_end = len(result)
                except (ValueError, TypeError):
                    # offset이 유효하지 않으면 그냥 추가
                    result.extend(content_bytes)
                    last_end = len(result)
            
            # depth 처리 (최대 검색 깊이)
            elif depth_key in options:
                try:
                    depth = int(options[depth_key])
                    
                    # 첫 번째 content이거나 distance가 없는 경우
                    if i == 0 or distance_key not in options:
                        # 0부터 (depth - len(content)) 사이의 랜덤 위치에 content 삽입
                        max_start = max(0, depth - len(content_bytes))
                        start = random.randint(0, max_start)
                        
                        # 시작 위치까지 랜덤 데이터로 채움
                        if start > 0:
                            padding = self._generate_random_bytes(start)
                            result.extend(padding)
                        
                        # content 추가
                        result.extend(content_bytes)
                        last_end = len(result)
                except (ValueError, TypeError):
                    # depth가 유효하지 않으면 그냥 추가
                    result.extend(content_bytes)
                    last_end = len(result)
            
            # distance 처리 (이전 content로부터의 상대적 거리)
            elif distance_key in options and i > 0:
                try:
                    distance = int(options[distance_key])
                    
                    # 이전 content 끝에서 distance만큼 떨어진 위치에 현재 content 삽입
                    start = last_end + distance
                    
                    # 현재 결과 길이가 start보다 작으면 랜덤 데이터로 채움
                    if len(result) < start:
                        padding = self._generate_random_bytes(start - len(result))
                        result.extend(padding)
                    
                    # content 추가
                    result.extend(content_bytes)
                    last_end = len(result)
                except (ValueError, TypeError):
                    # distance가 유효하지 않으면 그냥 추가
                    result.extend(content_bytes)
                    last_end = len(result)
            
            # within 처리 (이전 content로부터의 최대 거리)
            elif within_key in options and i > 0:
                try:
                    within = int(options[within_key])
                    
                    # 이전 content 끝에서 0부터 within 사이의 랜덤 위치에 현재 content 삽입
                    max_distance = min(within, within - len(content_bytes))
                    distance = random.randint(0, max(0, max_distance))
                    
                    start = last_end + distance
                    
                    # 현재 결과 길이가 start보다 작으면 랜덤 데이터로 채움
                    if len(result) < start:
                        padding = self._generate_random_bytes(start - len(result))
                        result.extend(padding)
                    
                    # content 추가
                    result.extend(content_bytes)
                    last_end = len(result)
                except (ValueError, TypeError):
                    # within이 유효하지 않으면 그냥 추가
                    result.extend(content_bytes)
                    last_end = len(result)
            
            # 옵션이 없는 경우 그냥 추가
            else:
                # 첫 번째가 아닌 content는 이전 content와 간격을 두기 위해 랜덤 데이터 추가
                if i > 0:
                    padding = self._generate_random_bytes(random.randint(1, 5))
                    result.extend(padding)
                
                result.extend(content_bytes)
                last_end = len(result)
        
        return bytes(result)
    
    def _generate_random_bytes(self, length: int) -> bytes:
        """지정된 길이의 랜덤 바이트 생성"""
        return bytes(random.randint(32, 126) for _ in range(length))
    
    def _generate_pcre_payload(self, pcre_patterns: List[str]) -> bytes:
        """PCRE 패턴에 맞는 페이로드 생성"""
        if not pcre_patterns:
            return b""
        
        # 첫 번째 PCRE 패턴 사용
        pcre = pcre_patterns[0]
        
        # PCRE 패턴에서 구분자 제거 (일반적으로 /pattern/flags 형식)
        if pcre.startswith('/') and '/' in pcre[1:]:
            last_slash = pcre.rindex('/')
            pattern = pcre[1:last_slash]
            flags = pcre[last_slash+1:]
        else:
            pattern = pcre
            flags = ""
        
        # 특정 취약점 패턴 인식 및 특수 처리
        # Adobe ColdFusion 디렉토리 트래버설 취약점 (CVE-2024-53961)
        if "(\x2e|%2[Ee]){2}(\x2f|\x5c|%2[Ff]|%5[Cc])" in pattern:
            # 디렉토리 트래버설 공격 페이로드 생성
            return b"GET /pms?module=logging&file_name=../../../etc/passwd"
        
        # 다른 일반적인 디렉토리 트래버설 패턴
        if "(\.\.|%2e%2e)" in pattern or "(\x2e\x2e|%2e%2e)" in pattern:
            return b"GET /pms?module=logging&file_name=../../../etc/passwd"
        
        # URL 인코딩된 경로 트래버설 패턴
        if "%2e%2e" in pattern or "%252e%252e" in pattern:
            return b"GET /pms?module=logging&file_name=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
        
        # 일반적인 PCRE 패턴 처리
        try:
            # 패턴에서 리터럴 문자열 추출
            # 정규식 메타문자 제거
            literal_parts = re.findall(r'[^\^\$\.\*\+\?\[\]\(\)\{\}\|\\]+', pattern)
            
            if literal_parts:
                # 리터럴 부분을 결합하여 기본 문자열 생성
                base_payload = ''.join(literal_parts)
                
                # 특수 문자 시퀀스 처리
                base_payload = base_payload.replace("\\x2e", ".").replace("\\x2f", "/").replace("\\x5c", "\\")
                base_payload = base_payload.replace("%2E", ".").replace("%2F", "/").replace("%5C", "\\")
                
                return base_payload.encode()
            
            # 패턴 분석을 통한 문자열 생성
            return self._create_matching_string(pattern)
        
        except Exception as e:
            print(f"Error generating PCRE payload: {str(e)}")
            # 오류 발생 시 기본 페이로드 반환
            return f"PCRE_PATTERN_{pcre.replace('/', '_')}".encode()
    
    def _create_matching_string(self, pattern: str) -> bytes:
        """정규식 패턴에 맞는 문자열 생성"""
        # 패턴 분석을 위한 간단한 규칙
        result = bytearray()
        
        # 특수 문자 및 이스케이프 시퀀스 처리
        i = 0
        while i < len(pattern):
            # 이스케이프된 문자 처리
            if pattern[i] == '\\' and i + 1 < len(pattern):
                next_char = pattern[i+1]
                
                # 16진수 이스케이프 시퀀스 (\x00)
                if next_char == 'x' and i + 3 < len(pattern):
                    try:
                        hex_val = int(pattern[i+2:i+4], 16)
                        result.append(hex_val)
                        i += 4
                        continue
                    except ValueError:
                        pass
                
                # 8진수 이스케이프 시퀀스 (\000)
                if next_char.isdigit() and i + 3 < len(pattern):
                    try:
                        oct_val = int(pattern[i+1:i+4], 8)
                        result.append(oct_val)
                        i += 4
                        continue
                    except ValueError:
                        pass
                
                # 일반적인 이스케이프 문자
                escape_map = {
                    'n': b'\n',
                    'r': b'\r',
                    't': b'\t',
                    '0': b'\0',
                    's': b' ',
                    'd': b'1',  # 숫자 대신 1
                    'w': b'a',  # 단어 문자 대신 a
                }
                
                if next_char in escape_map:
                    result.extend(escape_map[next_char])
                    i += 2
                    continue
                
                # 이스케이프된 특수 문자는 그대로 추가
                result.append(ord(next_char))
                i += 2
                continue
            
            # 문자 클래스 처리 [abc]
            if pattern[i] == '[':
                # 닫는 괄호 찾기
                j = i + 1
                while j < len(pattern) and pattern[j] != ']':
                    j += 1
                
                if j < len(pattern):
                    # 문자 클래스에서 하나의 문자 선택
                    char_class = pattern[i+1:j]
                    
                    # 부정 문자 클래스 [^abc]
                    if char_class.startswith('^'):
                        char_class = char_class[1:]
                        # 부정 클래스에서는 클래스에 없는 문자 선택
                        result.append(ord('X'))  # 임의의 문자
                    else:
                        # 문자 클래스에서 첫 번째 문자 또는 범위의 시작 문자 선택
                        if char_class:
                            if '-' in char_class and char_class.index('-') > 0:
                                # 범위에서 첫 번째 문자 선택
                                result.append(ord(char_class[0]))
                            else:
                                result.append(ord(char_class[0]))
                    
                    i = j + 1
                    continue
            
            # 수량자 처리 (*, +, ?, {n,m})
            if pattern[i] in '*+?{':
                # 수량자 앞의 문자나 그룹이 이미 처리되었으므로 건너뜀
                i += 1
                
                # {n,m} 형태의 수량자는 괄호 닫힘까지 건너뜀
                if pattern[i-1] == '{':
                    while i < len(pattern) and pattern[i] != '}':
                        i += 1
                    if i < len(pattern):
                        i += 1
                
                continue
            
            # 앵커 및 경계 처리 (^, $, \b)
            if pattern[i] in '^$':
                i += 1
                continue
            
            # 그룹 처리 ((...))
            if pattern[i] == '(':
                # 닫는 괄호 찾기 (중첩 괄호 고려)
                depth = 1
                j = i + 1
                
                while j < len(pattern) and depth > 0:
                    if pattern[j] == '(' and pattern[j-1] != '\\':
                        depth += 1
                    elif pattern[j] == ')' and pattern[j-1] != '\\':
                        depth -= 1
                    j += 1
                
                if depth == 0:
                    # 그룹 내용 추출 (괄호 제외)
                    group_content = pattern[i+1:j-1]
                    
                    # 비캡처 그룹 (?:...) 또는 다른 특수 그룹 처리
                    if group_content.startswith('?:'):
                        group_content = group_content[2:]
                    
                    # 그룹 내용에 대해 재귀적으로 처리
                    group_result = self._create_matching_string(group_content)
                    result.extend(group_result)
                    
                    i = j
                    continue
            
            # 선택 처리 (a|b)
            if pattern[i] == '|':
                # 선택의 왼쪽 부분은 이미 처리되었으므로 오른쪽 부분만 처리
                # 간단하게 하기 위해 첫 번째 선택지만 사용
                # 다음 그룹이나 패턴 끝까지 건너뜀
                i += 1
                continue
            
            # 일반 문자는 그대로 추가
            result.append(ord(pattern[i]))
            i += 1
        
        # 결과가 비어있으면 기본 문자열 생성
        if not result:
            # 패턴에서 리터럴 부분 추출 시도
            literal_parts = re.findall(r'[^\^\$\.\*\+\?\[\]\(\)\{\}\|\\]+', pattern)
            if literal_parts:
                return ''.join(literal_parts).encode()
            else:
                # 리터럴 부분이 없으면 랜덤 문자열 생성
                return ''.join(random.choices(string.ascii_letters + string.digits, k=10)).encode()
        
        return bytes(result)
    
    def _process_content_string(self, content: str) -> bytes:
        """content 문자열을 바이트로 변환"""
        result = b""
        i = 0
        
        while i < len(content):
            if content[i:i+2] == '\\x':
                # 16진수 이스케이프 시퀀스 처리
                try:
                    hex_val = int(content[i+2:i+4], 16)
                    result += bytes([hex_val])
                    i += 4
                except (ValueError, IndexError):
                    result += content[i:i+1].encode('latin-1')
                    i += 1
            elif content[i:i+1] == '\\':
                # 다른 이스케이프 시퀀스 처리
                if i+1 < len(content):
                    if content[i+1] == 'r':
                        result += b'\r'
                    elif content[i+1] == 'n':
                        result += b'\n'
                    elif content[i+1] == 't':
                        result += b'\t'
                    elif content[i+1] == '\\':
                        result += b'\\'
                    else:
                        result += content[i+1:i+2].encode('latin-1')
                    i += 2
                else:
                    result += b'\\'
                    i += 1
            else:
                # 일반 문자 처리
                result += content[i:i+1].encode('latin-1')
                i += 1
        
        return result 
