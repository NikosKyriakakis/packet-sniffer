#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct ether_hdr {
	unsigned char ether_dest_addr[ETHER_ADDR_LEN]; // Destination MAC address
	unsigned char ether_src_addr[ETHER_ADDR_LEN]; // Source MAC address
	unsigned short ether_type; // Type of Ethernet packet
};

struct ip_hdr {
	unsigned char ip_version_and_header_length; // Version and header length
	unsigned char ip_tos; // Type of service
	unsigned short ip_len; // Total length
	unsigned short ip_id; // Identification number
	unsigned short ip_frag_offset; // Fragment offset and flags
	unsigned char ip_ttl; // Time to live
	unsigned char ip_type; // Protocol type
	unsigned short ip_checksum; // Checksum
	unsigned int ip_src_addr; // Source IP address
	unsigned int ip_dest_addr; // Destination IP address
};

struct tcp_hdr {
	unsigned short tcp_src_port; // Source TCP port
	unsigned short tcp_dest_port; // Destination TCP port
	unsigned int tcp_seq; // TCP sequence number
	unsigned int tcp_ack; // TCP acknowledgment number
	unsigned char reserved:4; // 4 bits from the 6 bits of reserved space
	unsigned char tcp_offset:4; // TCP data offset for little-endian host
	unsigned char tcp_flags; // TCP flags (and 2 bits from reserved space)
	unsigned short tcp_window; // TCP window size
	unsigned short tcp_checksum; // TCP checksum
	unsigned short tcp_urgent; // TCP urgent pointer
};
