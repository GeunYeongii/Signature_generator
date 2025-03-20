from typing import Dict, List, Optional, Any
import re
import ipaddress

class RuleParser:
    """Snort 룰을 파싱하여 패킷 생성에 필요한 정보를 추출하는 클래스"""
    
    def __init__(self):
        # 변수 매핑 (실제 환경에서는 설정 파일에서 로드할 수 있음)
        self.variables = {
            "$EXTERNAL_NET": "192.168.1.1",
            "$HOME_NET": "10.0.0.0/24",
            "any": "0.0.0.0/0"
        }
        
        # 정규식 패턴 컴파일
        self.rule_pattern = re.compile(
            r'^(?P<action>\w+)\s+'
            r'(?P<protocol>\w+)\s+'
            r'(?P<src_ip>[^\s]+)\s+'
            r'(?P<src_port>[^\s]+)\s+'
            r'(?P<direction>->|<>)\s+'
            r'(?P<dst_ip>[^\s]+)\s+'
            r'(?P<dst_port>[^\s]+)\s+'
            r'\((?P<options>.*)\)'
        )
        
        # 옵션 정규식 패턴
        self.option_pattern = re.compile(r'(?:^|;)\s*(?P<key>[^:;]+)(?::(?P<value>[^;]+))?')
        
        # 16진수 패턴 (|00 01 02|)
        self.hex_pattern = re.compile(r'\|((?:[0-9A-Fa-f]{2}\s*)+)\|')
    
    def parse_rules(self, rules: List[str]) -> List[Dict[str, Any]]:
        """여러 Snort 룰을 파싱하여 패킷 생성에 필요한 정보 목록 반환"""
        parsed_rules = []
        
        for i, rule in enumerate(rules):
            try:
                parsed_rule = self.parse_rule(rule)
                if parsed_rule:
                    parsed_rules.append(parsed_rule)
            except Exception as e:
                print(f"Rule #{i+1} parsing error: {str(e)}")
                print(f"Rule: {rule}")
        
        return parsed_rules
    
    def parse_rule(self, rule: str) -> Optional[Dict[str, Any]]:
        """단일 Snort 룰을 파싱하여 패킷 생성에 필요한 정보 반환"""
        # 기본 룰 구조 파싱
        rule = rule.strip()
        if not rule or rule.startswith('#'):
            return None
        
        # 정규식으로 룰 파싱
        match = self.rule_pattern.match(rule)
        if not match:
            print(f"Failed to parse rule: {rule}")
            return None
        
        # 매칭된 그룹 추출
        groups = match.groupdict()
        
        # 변수 치환
        src_ip = self._replace_variable(groups['src_ip'])
        dst_ip = self._replace_variable(groups['dst_ip'])
        
        # 옵션 파싱
        options_str = groups['options']
        parsed_options = self._parse_options(options_str)
        
        # 결과 반환
        return {
            'action': groups['action'],
            'protocol': groups['protocol'].lower(),
            'src_ip': src_ip,
            'src_port': self._parse_port(groups['src_port']),
            'dst_ip': dst_ip,
            'dst_port': self._parse_port(groups['dst_port']),
            'direction': groups['direction'],
            'msg': parsed_options.get('msg', ''),
            'content': parsed_options.get('content', []),
            'pcre': parsed_options.get('pcre', []),
            'sid': parsed_options.get('sid', '0'),
            'rev': parsed_options.get('rev', '1'),
            'classtype': parsed_options.get('classtype', ''),
            'priority': parsed_options.get('priority', ''),
            'metadata': parsed_options.get('metadata', ''),
            'reference': parsed_options.get('reference', []),
            'raw_rule': rule,
            'options': parsed_options
        }
    
    def _replace_variable(self, value: str) -> str:
        """변수를 실제 값으로 치환"""
        # 직접 매핑된 변수 처리
        if value in self.variables:
            return self.variables[value]
        
        # $로 시작하는 변수 처리
        if value.startswith('$') and value in self.variables:
            return self.variables[value]
        
        # 변수가 아닌 경우 그대로 반환
        return value
    
    def _parse_port(self, port: str) -> Any:
        """포트 정보 파싱"""
        # 'any' 키워드 처리
        if port.lower() == 'any':
            return 'any'
        
        # 포트 범위 처리 (예: 1:1024)
        if ':' in port:
            parts = port.split(':')
            if len(parts) == 2:
                start, end = parts
                # 빈 값 처리 (예: :1024 또는 1024:)
                start_val = int(start) if start else 0
                end_val = int(end) if end else 65535
                return {'start': start_val, 'end': end_val}
        
        # 포트 목록 처리 (예: [80,443])
        if port.startswith('[') and port.endswith(']'):
            port_list = port[1:-1].split(',')
            return [int(p.strip()) for p in port_list if p.strip()]
        
        # 단일 포트 처리
        try:
            return int(port)
        except ValueError:
            # 숫자로 변환할 수 없는 경우 문자열 그대로 반환
            print(f"Warning: Could not parse port value: {port}")
            return port
    
    def _parse_options(self, options_str: str) -> Dict[str, Any]:
        """룰 옵션 파싱"""
        options = {}
        
        # 옵션 문자열 전처리
        options_str = options_str.strip()
        
        # 따옴표 내부의 세미콜론을 임시로 치환
        processed_str = ""
        in_quotes = False
        for char in options_str:
            if char == '"':
                in_quotes = not in_quotes
            
            if char == ';' and in_quotes:
                processed_str += '\x01'  # 임시 치환 문자
            else:
                processed_str += char
        
        # 세미콜론으로 옵션 분리
        parts = [p.strip() for p in processed_str.split(';') if p.strip()]
        
        # 각 옵션 파싱
        for part in parts:
            # 임시 치환 문자를 다시 세미콜론으로 변경
            part = part.replace('\x01', ';')
            
            if ':' in part:
                key, value = part.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                # 따옴표 제거
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                
                # 특수 처리가 필요한 옵션
                if key in ['content', 'pcre', 'reference']:
                    if key not in options:
                        options[key] = []
                    
                    # content 옵션의 16진수 처리
                    if key == 'content':
                        # 16진수 패턴 처리
                        value = self._process_hex_content(value)
                    
                    options[key].append(value)
                else:
                    options[key] = value
            else:
                # 값이 없는 옵션 (예: nocase)
                options[part.strip()] = True
        
        return options
    
    def _process_hex_content(self, content: str) -> str:
        """content 옵션의 16진수 패턴 처리"""
        # |00 01 02| 형태의 16진수 패턴 찾기
        def replace_hex(match):
            hex_str = match.group(1).replace(' ', '')
            try:
                # 16진수를 바이트로 변환
                hex_bytes = bytes.fromhex(hex_str)
                # 바이트를 문자열로 변환 (이스케이프 시퀀스 유지)
                return ''.join(f'\\x{b:02x}' for b in hex_bytes)
            except ValueError:
                print(f"Warning: Invalid hex sequence: {match.group(0)}")
                return match.group(0)
        
        # 16진수 패턴 치환
        return re.sub(self.hex_pattern, replace_hex, content)
    
    def get_ip_from_cidr(self, cidr: str) -> str:
        """CIDR 표기법에서 유효한 IP 주소 추출"""
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
