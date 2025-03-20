import argparse
import sys
from typing import List, Optional
import importlib.util
import subprocess
import sys
import os

# 필요한 패키지 확인 및 설치
required_packages = ['scapy', 'colorama']

def check_and_install_packages():
    # 일반 패키지 확인 및 설치
    for package in required_packages:
        if importlib.util.find_spec(package) is None:
            print(f"Required package '{package}' not found. Installing...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"Successfully installed {package}")
            except Exception as e:
                print(f"Error installing {package}: {str(e)}")
                print(f"Please install {package} manually: pip install {package}")
                sys.exit(1)

# 패키지 확인 및 설치
check_and_install_packages()

# 이제 필요한 모듈 가져오기
try:
    from rule_parser import RuleParser
    from packet_generator import PacketGenerator
    from output_handler import OutputHandler
    import socket
    import ipaddress
except ImportError as e:
    print(f"Error importing modules: {str(e)}")
    print("Please make sure all required packages are installed")
    sys.exit(1)

def read_rules_from_file(filename: str) -> List[str]:
    """파일에서 Snort 룰 읽기"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        print(f"File reading error: {str(e)}")
        return []

def get_local_ip() -> str:
    """로컬 IP 주소 가져오기"""
    try:
        # 인터넷에 연결하지 않고 로컬 IP 가져오기
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        # 실패 시 기본값 반환
        return "127.0.0.1"

def validate_ip(ip: str) -> bool:
    """IP 주소 유효성 검사"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(description='Snort Rule Signature Generator')
    
    # 입력 옵션
    parser.add_argument('-f', '--file', required=True, help='Snort rules file')
    
    # 출력 옵션 (PCAP 파일 저장은 선택적)
    parser.add_argument('-o', '--output', help='Output PCAP file path (optional)')
    parser.add_argument('--no-responses', action='store_true', help='Do not include response packets in PCAP')
    
    # 추가 옵션
    parser.add_argument('--interval', type=float, default=0.1, help='Packet transmission interval (seconds)')
    parser.add_argument('-d', '--dst-ip', required=True, help='Destination IP address')
    parser.add_argument('-s', '--src-ip', help='Source IP address (optional)')
    
    args = parser.parse_args()
    
    # IP 주소 유효성 검사
    if not validate_ip(args.dst_ip):
        print(f"Error: Invalid destination IP address: {args.dst_ip}")
        return
    
    if args.src_ip and not validate_ip(args.src_ip):
        print(f"Error: Invalid source IP address: {args.src_ip}")
        return
    
    # 출발지 IP가 지정되지 않은 경우 로컬 IP 사용
    src_ip = args.src_ip if args.src_ip else get_local_ip()
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {args.dst_ip}")
    
    # 룰 파일 읽기
    rules = read_rules_from_file(args.file)
    
    if not rules:
        print("No Snort rules to process.")
        return
    
    print(f"Processing {len(rules)} Snort rules...")
    
    # 룰 파싱
    rule_parser = RuleParser()
    parsed_rules = rule_parser.parse_rules(rules)
    
    if not parsed_rules:
        print("No valid Snort rules found.")
        return
    
    print(f"Parsed {len(parsed_rules)} valid rules.")
    
    # 패킷 생성 - 명령줄 옵션으로 지정한 IP 전달
    packet_generator = PacketGenerator()
    packets = packet_generator.generate_packets(parsed_rules, args.dst_ip, src_ip)
    
    if not packets:
        print("No packets generated.")
        return
    
    print(f"Generated {len(packets)} packets.")
    
    # 출력 처리
    output_handler = OutputHandler()
    
    # 선택적으로 PCAP 파일 저장
    if args.output:
        include_responses = not args.no_responses
        pcap_path = output_handler.save_to_pcap(packets, args.output, include_responses)
        if include_responses:
            print(f"Saved packets and responses to PCAP file: {pcap_path}")
        else:
            print(f"Saved packets to PCAP file: {pcap_path}")
    
    # 패킷 전송
    sent_count = output_handler.send_packets(
        packets, 
        interval=args.interval
    )
    print(f"Sent {sent_count} packets over the network.")

if __name__ == "__main__":
    main() 
