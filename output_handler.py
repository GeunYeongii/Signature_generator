from typing import List, Tuple, Dict, Any
from scapy.all import wrpcap, send, conf, IP, TCP, UDP, ICMP, sr1, sniff, PcapWriter
from scapy.packet import Packet
import time
import os
import datetime
import threading
from colorama import init, Fore, Style

# Initialize color output
init()

class OutputHandler:
    """Class for saving or sending generated packets"""
    
    def __init__(self):
        # Set up log directory
        self.log_dir = "logs"
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # Daily log file setup (YYYY-MM-DD.log)
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        self.log_file = os.path.join(self.log_dir, f"{today}.log")
        
        # Mark the start of a new session
        self.log_session_start()
        
        # For packet capture
        self.capture_packets = []
        self.is_capturing = False
        self.capture_thread = None
    
    def log_session_start(self):
        """Log the start of a new execution session"""
        # Check if file exists, if so open in append mode
        file_exists = os.path.exists(self.log_file)
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            # Add separator if file already exists
            if file_exists:
                f.write("\n\n")
                
            f.write("=" * 80 + "\n")
            f.write(f"Snort Rule Signature Generator - Session Start: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
    
    def log_message(self, message, level="INFO", print_console=True):
        """Record log message"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')  # Only show time (date is in filename)
        
        # Set color based on log level
        if level == "INFO":
            color = Fore.GREEN
        elif level == "WARNING":
            color = Fore.YELLOW
        elif level == "ERROR":
            color = Fore.RED
        else:
            color = Fore.WHITE
            
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        # Console output
        if print_console:
            print(f"{color}{formatted_message}{Style.RESET_ALL}")
            
        # File recording - using UTF-8 encoding
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(formatted_message + "\n")
    
    def start_packet_capture(self):
        """Start capturing packets on the network interface"""
        if self.is_capturing:
            self.log_message("Packet capture is already running", level="WARNING")
            return
        
        self.is_capturing = True
        self.capture_packets = []
        
        # Start capture in a separate thread
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        self.log_message("Packet capture started")
    
    def _capture_packets(self):
        """Background thread function for packet capture"""
        try:
            # Capture all packets
            sniff(prn=lambda pkt: self.capture_packets.append(pkt), 
                  store=False, 
                  stop_filter=lambda pkt: not self.is_capturing)
        except Exception as e:
            self.log_message(f"Error in packet capture: {str(e)}", level="ERROR")
    
    def stop_packet_capture(self):
        """Stop the packet capture"""
        if not self.is_capturing:
            return
        
        self.is_capturing = False
        
        # Wait for the capture thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
        
        self.log_message(f"Packet capture stopped. Captured {len(self.capture_packets)} packets.")
    
    def save_to_pcap(self, packets: List[Tuple[Dict[str, Any], Packet]], filename: str, include_responses: bool = False) -> str:
        """Save packets to PCAP file"""
        # Check file extension
        if not filename.endswith('.pcap'):
            filename += '.pcap'
            
        # Check directory
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        
        # 패킷 리스트 추출
        packet_list = [packet for _, packet in packets]
        
        # Save as PCAP file
        wrpcap(filename, packet_list)
        self.log_message(f"Saved {len(packet_list)} packets to PCAP file: {os.path.abspath(filename)}")
        
        return os.path.abspath(filename)
    
    def send_packets(self, packets: List[Tuple[Dict[str, Any], Packet]], 
                    interval: float = 0.1, dst_ip: str = None, src_ip: str = None,
                    save_only: bool = False) -> int:
        """Send packets over the network"""
        sent_count = 0
        success_count = 0
        blocked_count = 0
        timeout_count = 0
        error_count = 0
        
        # Statistics by protocol
        protocol_stats = {
            'TCP': {'sent': 0, 'success': 0, 'blocked': 0, 'timeout': 0},
            'UDP': {'sent': 0, 'success': 0, 'blocked': 0, 'timeout': 0},
            'ICMP': {'sent': 0, 'success': 0, 'blocked': 0, 'timeout': 0},
            'OTHER': {'sent': 0, 'success': 0, 'blocked': 0, 'timeout': 0}
        }
        
        # Response time tracking
        response_times = []
        
        if not save_only:
            session_time = datetime.datetime.now().strftime('%H:%M:%S')
            self.log_message(f"Packet transmission session started [{session_time}]")
            self.log_message("=" * 60)
        
        start_session_time = time.time()
        
        for i, (rule, packet) in enumerate(packets, 1):
            try:
                # 패킷 복제 (원본 변경 방지)
                packet = packet.copy()
                
                # 패킷 정보 로깅을 위한 SID 미리 가져오기
                sid = rule.get('sid', 'unknown')
                
                # IP 주소는 이미 패킷 생성 시 설정되었으므로 변경하지 않음
                # 단, 명시적으로 지정된 경우에만 변경
                if dst_ip and packet.haslayer(IP):
                    packet[IP].dst = dst_ip
                
                if src_ip and packet.haslayer(IP):
                    packet[IP].src = src_ip
                
                # 프로토콜 식별
                protocol = "OTHER"
                if packet.haslayer(IP):
                    if packet.haslayer(TCP):
                        protocol = "TCP"
                    elif packet.haslayer(UDP):
                        protocol = "UDP"
                    elif packet.haslayer(ICMP):
                        protocol = "ICMP"
                
                # 패킷 정보 로깅
                msg = rule.get('msg', '')
                
                if not save_only:
                    self.log_message(f"Sending packet #{i} (SID: {sid})")
                    if msg:
                        self.log_message(f"  - Message: {msg}")
                    self.log_message(f"  - Protocol: {protocol}")
                    
                    if packet.haslayer(IP):
                        sport = getattr(packet.getlayer(1), 'sport', '?') if packet.haslayer(TCP) or packet.haslayer(UDP) else '?'
                        dport = getattr(packet.getlayer(1), 'dport', '?') if packet.haslayer(TCP) or packet.haslayer(UDP) else '?'
                        self.log_message(f"  - Source: {packet[IP].src}:{sport}")
                        self.log_message(f"  - Destination: {packet[IP].dst}:{dport}")
                
                # 패킷 전송 시간 측정
                start_time = time.time()
                
                # 패킷 전송
                if save_only:
                    # PCAP 저장 모드에서는 실제로 전송
                    send(packet, verbose=0)
                else:
                    # 실제 네트워크로 전송하고 응답 대기
                    response = sr1(packet, timeout=2, verbose=0)
                    
                    # 응답 처리
                    end_time = time.time()
                    response_time = (end_time - start_time) * 1000  # ms로 변환
                    
                    if response:
                        success_count += 1
                        protocol_stats[protocol]['success'] += 1
                        response_times.append(response_time)
                        self.log_message(f"  - Response received in {response_time:.2f}ms")
                    else:
                        # 응답이 없는 경우 (차단 또는 타임아웃)
                        if protocol == "TCP":
                            # TCP의 경우 RST 응답이 없으면 차단으로 간주
                            blocked_count += 1
                            protocol_stats[protocol]['blocked'] += 1
                            self.log_message(f"  - No response (likely blocked)", level="WARNING")
                        else:
                            # 다른 프로토콜은 타임아웃으로 간주
                            timeout_count += 1
                            protocol_stats[protocol]['timeout'] += 1
                            self.log_message(f"  - Timeout (no response)", level="WARNING")
                
                # 전송 성공 카운트 증가
                sent_count += 1
                protocol_stats[protocol]['sent'] += 1
                
                # 패킷 간 간격 유지
                if i < len(packets):
                    time.sleep(interval)
                    
            except Exception as e:
                error_count += 1
                # sid 변수가 정의되지 않았을 수 있으므로 안전하게 처리
                try:
                    self.log_message(f"Error sending packet #{i} (SID: {sid}): {str(e)}", level="ERROR")
                except:
                    self.log_message(f"Error sending packet #{i}: {str(e)}", level="ERROR")
        
        # 세션 종료 시간 측정
        end_session_time = time.time()
        total_time = end_session_time - start_session_time
        
        if save_only:
            return sent_count
        
        # 평균 응답 시간 계산
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Transmission summary
        self.log_message("=" * 60)
        self.log_message(f"Packet Transmission Statistics")
        self.log_message("=" * 60)
        
        # Basic statistics
        self.log_message(f"Total packets: {len(packets)}")
        self.log_message(f"Packets sent: {sent_count}")
        self.log_message(f"Successful responses: {success_count}")
        self.log_message(f"Blocked packets: {blocked_count}")
        self.log_message(f"Timeouts: {timeout_count}")
        self.log_message(f"Errors: {error_count}")
        
        # Success rate
        if sent_count > 0:
            success_rate = (success_count / sent_count) * 100
            self.log_message(f"Success rate: {success_rate:.1f}%")
        
        # Response time statistics
        if response_times:
            self.log_message(f"Average response time: {avg_response_time:.2f}ms")
            self.log_message(f"Min response time: {min(response_times):.2f}ms")
            self.log_message(f"Max response time: {max(response_times):.2f}ms")
        
        # Protocol statistics
        self.log_message("\nProtocol Statistics:")
        for protocol, stats in protocol_stats.items():
            if stats['sent'] > 0:
                self.log_message(f"  {protocol}:")
                self.log_message(f"    - Sent: {stats['sent']}")
                self.log_message(f"    - Successful: {stats['success']}")
                self.log_message(f"    - Blocked: {stats['blocked']}")
                self.log_message(f"    - Timeouts: {stats['timeout']}")
                
                # Success rate by protocol
                protocol_success_rate = (stats['success'] / stats['sent']) * 100
                self.log_message(f"    - Success rate: {protocol_success_rate:.1f}%")
        
        # Session duration
        self.log_message(f"\nSession duration: {total_time:.2f} seconds")
        self.log_message(f"Log file: {os.path.abspath(self.log_file)}")
        
        # Visual representation of results
        self.print_visual_stats(sent_count, success_count, blocked_count, timeout_count, error_count)
        
        return sent_count
    
    def print_visual_stats(self, sent, success, blocked, timeout, error):
        """Print visual statistics using ASCII art"""
        self.log_message("\nVisual Statistics:", print_console=True)
        
        # Calculate percentages
        if sent > 0:
            success_pct = (success / sent) * 100
            blocked_pct = (blocked / sent) * 100
            timeout_pct = (timeout / sent) * 100
            error_pct = (error / sent) * 100
            
            # Create bar chart
            bar_width = 50  # characters
            
            # Success bar
            success_bar = int((success_pct / 100) * bar_width)
            success_str = f"{Fore.GREEN}{'█' * success_bar}{Style.RESET_ALL}"
            
            # Blocked bar
            blocked_bar = int((blocked_pct / 100) * bar_width)
            blocked_str = f"{Fore.YELLOW}{'█' * blocked_bar}{Style.RESET_ALL}"
            
            # Timeout bar
            timeout_bar = int((timeout_pct / 100) * bar_width)
            timeout_str = f"{Fore.RED}{'█' * timeout_bar}{Style.RESET_ALL}"
            
            # Error bar
            error_bar = int((error_pct / 100) * bar_width)
            error_str = f"{Fore.MAGENTA}{'█' * error_bar}{Style.RESET_ALL}"
            
            # Print bars
            print(f"\n{Fore.WHITE}Packet Transmission Results:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Success   ({success_pct:5.1f}%): {success_str} {success}/{sent}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Blocked   ({blocked_pct:5.1f}%): {blocked_str} {blocked}/{sent}{Style.RESET_ALL}")
            print(f"{Fore.RED}Timeout   ({timeout_pct:5.1f}%): {timeout_str} {timeout}/{sent}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}Error     ({error_pct:5.1f}%): {error_str} {error}/{sent}{Style.RESET_ALL}")
            print("\n")
            
            # Add to log file (without colors)
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write("\nPacket Transmission Results:\n")
                f.write(f"Success   ({success_pct:5.1f}%): {'#' * success_bar} {success}/{sent}\n")
                f.write(f"Blocked   ({blocked_pct:5.1f}%): {'#' * blocked_bar} {blocked}/{sent}\n")
                f.write(f"Timeout   ({timeout_pct:5.1f}%): {'#' * timeout_bar} {timeout}/{sent}\n")
                f.write(f"Error     ({error_pct:5.1f}%): {'#' * error_bar} {error}/{sent}\n\n") 
