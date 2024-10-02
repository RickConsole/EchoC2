# EchoC2
EchoC2 allows for command and control over ICMP (ping). 

### Features
- **ICMP Only**: Utilizes ICMP Echo Request/Reply 
- **Robust**: Can receive long command outputs via fragmented ICMP replies
- **Covert**: Maintains standard ping packet lengths + responds to regular pings

While `echoc2.py` can operate in both client and server mode, `agent.py` is a stripped down version which only has the features required for a compromised machine.

### Usage
On your target (requires root):
```bash
sudo python3 agent.py
```

On your attacker (also root)
```bash
sudo python3 echoc2.py client <IP of target>
```

### Configuring MAX_PACKET_SIZE
When transmitting data over ICMP there is a trade-off when trying to be stealthy:

**Increased MAX_PACKET_SIZE**: This will allow you to transmit more data over fewer total ICMP packets, but their varying size may draw attention

**Fixed MAX_PACKET_SIZE**: By setting `MAX_PACKET_SIZE` to `84`, it will send ICMP packets with a fixed length of `98` which is the standard length of an ICMP reply. However, this will generate significantly more ICMP replies, which may draw attention in quieter networks. 