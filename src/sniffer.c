#include <pcap.h>

#include "utils.h"
#include "net_structs.h"

#define READ_TIMEOUT 0
#define PROMISCUOUS_MODE 1
#define PACKET_SIZE 4096

static void decode_ethernet(const u_char *header_ptr)
{
	/**
		Display ethernet details

		header_ptr: a reference to the header object
	*/
	const struct ether_hdr *ethernet_header = (const struct ether_hdr *)header_ptr;
	
	printf("Ethernet Layer\n");
	printf("-------------\n");
	printf("Origin: %02x", ethernet_header->ether_src_addr[0]);
	for (int i = 1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_src_addr[i]);	

	printf("\tDestination: %02x", ethernet_header->ether_dest_addr[0]);
	for(int i=1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_dest_addr[i]);
		
	printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

static void decode_ip(const u_char *header_ptr)
{
	/**
			Display ip details
	
			header_ptr: a reference to the header object
	*/
	const struct ip_hdr *ip_header = (const struct ip_hdr *)header_ptr;

	printf("\nIP Layer\n");
	printf("-------------\n");
	
	struct in_addr ip_wrapper;

	ip_wrapper.s_addr = ip_header->ip_src_addr;
	printf("Origin: %s\t", inet_ntoa(ip_wrapper));

	ip_wrapper.s_addr = ip_header->ip_dest_addr;
	printf("Destination: %s\t", inet_ntoa(ip_wrapper));
	
	printf("Type: %u\t\t", (u_int) ip_header->ip_type);
	printf("ID: %hu\t\tSize: %hu\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

static u_int decode_tcp(const u_char *header_ptr)
{
	/**
			Display TCP related details
	
			header_ptr: a reference to the header object
	*/
	printf("\nTCP Layer\n");
	printf("-------------\n");

	const struct tcp_hdr *tcp_header = (const struct tcp_hdr *)header_ptr;
	
	printf("Origin port: %hu\t", ntohs(tcp_header->tcp_src_port));
	printf("Destination port: %hu\n", ntohs(tcp_header->tcp_dest_port));
	printf("Seq #: %u\t", ntohl(tcp_header->tcp_seq));
	printf("Ack #: %u\n", ntohl(tcp_header->tcp_ack));
	
	const u_int header_size = 4 * tcp_header->tcp_offset;
	printf("Header Size: %u\nFlags: ", header_size);
	
	if(tcp_header->tcp_flags & TCP_FIN)
		printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("URG ");
	printf("\n");

	return header_size;
}

static void process_packet (
	u_char *args, 
	const struct pcap_pkthdr *cap_header, 
	const u_char *packet
)
{
	/**
		Callback function to process and decode a captured packet

		args: additional user defined arguments (optional)
		cap_header: reference to the captured header (contains meta-data)
		packet: a reference to the captured packet itself
	*/
	printf("\n=========================== Captured packet - %d bytes ===========================\n", cap_header->len);

	// Pass the initial pointer
	// to extract ethernet related info
	decode_ethernet(packet);

	// Skip the ethernet part and use 
	// the part which contains the IP info
	decode_ip(packet + ETHER_HDR_LEN);

	// Finally, skip both ethernet and IP sections and process the TCP section
	const u_int tcp_header_size = decode_tcp(packet + ETHER_HDR_LEN + sizeof(struct ip_hdr));

	// Now we can calculate the total header size
	// Important in order to know where the captured data begins
	const int total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_size;

	// Extract the captured data
	u_char *payload = (u_char *)packet + total_header_size;
	const int payload_size = cap_header->len - total_header_size;
	if (payload_size > 0) {
		printf("\nCaptured data dump: %d bytes\n", payload_size);
		printf("----------------------------------------\n");
		raw_dump(payload, payload_size);
	} else
		printf("\nNo captured data\n");
}

int main(int argc, char *argv[])
{
	// A buffer to be used for error logging
	char error_buffer[PCAP_ERRBUF_SIZE];

	// Look for a suitable interface 
	// to attach and intercept packets
	char *device = pcap_lookupdev(error_buffer);
	if (device == NULL)
		fatal("pcap_lookupdev", error_buffer);

	printf("Sniffer active on device %s\n", device);

	// Get a handle on the available interface
	// Also, set it to promiscuous mode 
	// and disable read timeouts
	pcap_t *pcap_handle = pcap_open_live (
		device, 
		PACKET_SIZE, 
		PROMISCUOUS_MODE, 
		READ_TIMEOUT, 
		error_buffer
	);
	
	if (pcap_handle == NULL)
		fatal("pcap_open_live", error_buffer);

	// Each captured packet is assigned 
	// to the "process_packet" callback function
	pcap_loop(pcap_handle, -1, process_packet, NULL);

	// Close the sniffer
	pcap_close(pcap_handle);
}
