"""
Traffic Capture module for the NGFW system
Handles packet capture and preprocessing
"""

import asyncio
import time
import struct
import socket
from typing import Optional, Callable, Dict, Any
import logging
from dataclasses import dataclass

try:
    import pcap
    PCAP_AVAILABLE = True
except ImportError:
    PCAP_AVAILABLE = False
    logging.warning("pcap not available, using socket-based capture")

from utils.config import Config
from core.firewall_engine import PacketInfo, FirewallEngine

logger = logging.getLogger(__name__)

@dataclass
class CaptureStats:
    """Traffic capture statistics"""
    packets_captured: int = 0
    bytes_captured: int = 0
    dropped_packets: int = 0
    start_time: float = 0
    last_packet_time: float = 0

class TrafficCapture:
    """Network traffic capture and preprocessing"""
    
    def __init__(self, config: Config, firewall_engine: FirewallEngine):
        self.config = config
        self.firewall_engine = firewall_engine
        self.stats = CaptureStats()
        self.running = False
        self.capture_task = None
        
        # Packet processing queue
        self.packet_queue = asyncio.Queue(maxsize=10000)
        self.processing_tasks = []
        
        # Performance tracking
        self.last_stats_time = time.time()
        self.packets_per_second = 0.0
        self.bytes_per_second = 0.0
    
    async def initialize(self):
        """Initialize traffic capture"""
        logger.info("Initializing Traffic Capture...")
        
        # Check if pcap is available
        if not PCAP_AVAILABLE:
            logger.warning("pcap not available, using socket-based capture")
        
        # Start packet processing workers
        num_workers = min(4, asyncio.get_event_loop().get_debug() and 1 or 4)
        for i in range(num_workers):
            task = asyncio.create_task(self._packet_processor(f"worker-{i}"))
            self.processing_tasks.append(task)
        
        logger.info(f"Traffic Capture initialized with {num_workers} workers")
    
    async def start(self):
        """Start traffic capture"""
        logger.info("Starting Traffic Capture...")
        self.running = True
        self.stats.start_time = time.time()
        
        # Start capture task
        if PCAP_AVAILABLE:
            self.capture_task = asyncio.create_task(self._pcap_capture())
        else:
            self.capture_task = asyncio.create_task(self._socket_capture())
        
        # Start statistics reporting
        asyncio.create_task(self._stats_reporter())
        
        logger.info("Traffic Capture started")
    
    async def stop(self):
        """Stop traffic capture"""
        logger.info("Stopping Traffic Capture...")
        self.running = False
        
        # Cancel capture task
        if self.capture_task:
            self.capture_task.cancel()
            try:
                await self.capture_task
            except asyncio.CancelledError:
                pass
        
        # Cancel processing tasks
        for task in self.processing_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        logger.info("Traffic Capture stopped")
    
    async def _pcap_capture(self):
        """Capture packets using pcap"""
        try:
            # Open pcap interface
            pc = pcap.pcap(name=self.config.network.interface, 
                          promisc=self.config.network.promiscuous_mode,
                          timeout_ms=self.config.network.capture_timeout)
            
            logger.info(f"Capturing on interface: {self.config.network.interface}")
            
            while self.running:
                try:
                    # Capture packet
                    timestamp, packet = pc.next()
                    if packet is None:
                        continue
                    
                    # Parse packet
                    packet_info = self._parse_packet(packet, timestamp)
                    if packet_info:
                        # Add to processing queue
                        try:
                            self.packet_queue.put_nowait(packet_info)
                            self.stats.packets_captured += 1
                            self.stats.bytes_captured += len(packet)
                            self.stats.last_packet_time = timestamp
                        except asyncio.QueueFull:
                            self.stats.dropped_packets += 1
                            logger.warning("Packet queue full, dropping packet")
                
                except Exception as e:
                    logger.error(f"Error capturing packet: {e}")
                    await asyncio.sleep(0.001)  # Small delay on error
        
        except Exception as e:
            logger.error(f"Failed to start pcap capture: {e}")
            # Fallback to socket capture
            await self._socket_capture()
    
    async def _socket_capture(self):
        """Capture packets using raw sockets (fallback)"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(1.0)  # 1 second timeout
            
            logger.info(f"Using socket capture on interface: {self.config.network.interface}")
            
            while self.running:
                try:
                    # Receive packet
                    packet, addr = sock.recvfrom(self.config.network.max_packet_size)
                    timestamp = time.time()
                    
                    # Parse packet
                    packet_info = self._parse_packet(packet, timestamp)
                    if packet_info:
                        # Add to processing queue
                        try:
                            self.packet_queue.put_nowait(packet_info)
                            self.stats.packets_captured += 1
                            self.stats.bytes_captured += len(packet)
                            self.stats.last_packet_time = timestamp
                        except asyncio.QueueFull:
                            self.stats.dropped_packets += 1
                            logger.warning("Packet queue full, dropping packet")
                
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error in socket capture: {e}")
                    await asyncio.sleep(0.001)
        
        except Exception as e:
            logger.error(f"Failed to start socket capture: {e}")
    
    def _parse_packet(self, packet: bytes, timestamp: float) -> Optional[PacketInfo]:
        """Parse raw packet data into PacketInfo"""
        try:
            if len(packet) < 14:  # Minimum Ethernet header size
                return None
            
            # Parse Ethernet header
            eth_header = struct.unpack('!6s6sH', packet[:14])
            dst_mac = eth_header[0]
            src_mac = eth_header[1]
            eth_type = eth_header[2]
            
            # Check if it's an IP packet
            if eth_type != 0x0800:  # IPv4
                return None
            
            # Parse IP header
            if len(packet) < 34:  # Ethernet + IP header minimum
                return None
            
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0x0F
            
            if version != 4:  # Only IPv4
                return None
            
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Parse TCP/UDP header if present
            src_port = 0
            dst_port = 0
            payload_offset = 14 + (ihl * 4)
            
            if protocol == 6:  # TCP
                if len(packet) >= payload_offset + 4:
                    tcp_header = struct.unpack('!HH', packet[payload_offset:payload_offset + 4])
                    src_port = tcp_header[0]
                    dst_port = tcp_header[1]
                    payload_offset += 20  # TCP header size (simplified)
            elif protocol == 17:  # UDP
                if len(packet) >= payload_offset + 4:
                    udp_header = struct.unpack('!HH', packet[payload_offset:payload_offset + 4])
                    src_port = udp_header[0]
                    dst_port = udp_header[1]
                    payload_offset += 8  # UDP header size
            
            # Extract payload
            payload = packet[payload_offset:] if len(packet) > payload_offset else b''
            
            # Determine protocol name
            protocol_name = {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(protocol, 'unknown')
            
            return PacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                payload=payload,
                timestamp=timestamp,
                size=len(packet),
                flags={}
            )
        
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    async def _packet_processor(self, worker_name: str):
        """Process packets from the queue"""
        logger.info(f"Starting packet processor: {worker_name}")
        
        while self.running:
            try:
                # Get packet from queue
                packet_info = await asyncio.wait_for(
                    self.packet_queue.get(), 
                    timeout=1.0
                )
                
                # Process packet through firewall engine
                if self.firewall_engine:
                    action, threat_info = await self.firewall_engine.process_packet(packet_info)
                    
                    # Log action if not allow
                    if action.value != "allow":
                        logger.info(
                            f"{worker_name}: {action.value.upper()} packet "
                            f"{packet_info.src_ip}:{packet_info.src_port} -> "
                            f"{packet_info.dst_ip}:{packet_info.dst_port}"
                        )
                
                # Mark task as done
                self.packet_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in packet processor {worker_name}: {e}")
                await asyncio.sleep(0.1)
        
        logger.info(f"Packet processor {worker_name} stopped")
    
    async def _stats_reporter(self):
        """Report capture statistics"""
        while self.running:
            try:
                current_time = time.time()
                time_diff = current_time - self.last_stats_time
                
                if time_diff > 0:
                    # Calculate rates
                    packets_diff = self.stats.packets_captured - (self.stats.packets_captured - self.stats.packets_captured)
                    bytes_diff = self.stats.bytes_captured - (self.stats.bytes_captured - self.stats.bytes_captured)
                    
                    self.packets_per_second = packets_diff / time_diff
                    self.bytes_per_second = bytes_diff / time_diff
                
                # Log statistics every 30 seconds
                if int(current_time) % 30 == 0:
                    logger.info(
                        f"Capture Stats - Packets: {self.stats.packets_captured}, "
                        f"Bytes: {self.stats.bytes_captured}, "
                        f"Dropped: {self.stats.dropped_packets}, "
                        f"Rate: {self.packets_per_second:.1f} pps, "
                        f"{self.bytes_per_second:.1f} bps"
                    )
                
                self.last_stats_time = current_time
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in stats reporter: {e}")
                await asyncio.sleep(1)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics"""
        current_time = time.time()
        uptime = current_time - self.stats.start_time if self.stats.start_time > 0 else 0
        
        return {
            "packets_captured": self.stats.packets_captured,
            "bytes_captured": self.stats.bytes_captured,
            "dropped_packets": self.stats.dropped_packets,
            "uptime_seconds": uptime,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "queue_size": self.packet_queue.qsize(),
            "processing_workers": len(self.processing_tasks)
        }