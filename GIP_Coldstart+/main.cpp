#include <wiringPi.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
// LED Pin - wiringPi pin 0 is BCM_GPIO 17.
// we have to use BCM numbering when initializing with wiringPiSetupSys
// when choosing a different pin number please use the BCM numbering, also
// update the Property Pages - Build Events - Remote Post-Build Event command
// which uses gpio export for setup for wiringPiSetupSys
#define	LED	17
void pcapCallback(u_char* arg_array, const struct pcap_pkthdr* h, const u_char* packet) {
	if (h->len == 66 && packet[34] == 0x7e && packet[35] == 0xed) {
		// This is a packet for us, we can process it
		fprintf(stderr, "Received packet with destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			packet[34], packet[35], packet[36], packet[37], packet[38], packet[39]);
	}

}
int main(int argc, char** argv)
{
	//Working
	const unsigned char beaconPacketData[80] = {  0x0, 0x0, 0x18, 0x0, 0x2b, 0x0, 0x0, 0x0, 0x7b, 0x84, 0xb5, 0x18, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x99, 0x9, 0x0, 0x0, 0xb1, 0x00, 0x80, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x62, 0x45,

		0xff, 0xff, 0xff,

		0x81, 0x62, 0x45,

		//Change these to your own values from "airodump-ng -c 1" every dongle mac address starts with 62:45
		0xff, 0xff, 0xff,

		0x81, 0xc0, 0xe9, 0x2f, 0x9f, 0xc2, 0x16, 0x0, 0x0, 0x0, 0x0, 0x64, 0x0, 0x31, 0xc6, 0x0, 0x0, 0xdd, 0xc, 0x0, 0x50, 0xf2, 0x11, 0x1, 0x10, 0x0, 0xa1, 0x28, 0x9d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	size_t packet_size = sizeof(beaconPacketData);
	pcap_if_t* dev; /* name of the device to use */
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp_prog;
	u_char* userHandle = NULL;
	pcap_t* handle = NULL;
	/* ask pcap to find a valid device for use to sniff on */
	int ret = pcap_init(0, errbuf);
	ret = pcap_findalldevs(&dev, errbuf);
	handle = pcap_open_live(
		"wlan0mon",
		BUFSIZ,
		1,
		1,
		errbuf
	);
	if (handle == NULL) {
		fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
		return 1;
	}
	wiringPiSetupSys();

	pinMode(LED, OUTPUT);

	ret = pcap_compile(handle, &fp_prog, "wlan subtype assoc-req", 1, PCAP_NETMASK_UNKNOWN);
	if (ret == -1) {
		fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
		return 1;
	}
	//ret = pcap_setfilter(handle, &fp_prog);
	while (true)
	{
		ret = pcap_sendpacket(handle, beaconPacketData, packet_size);
		pcap_dispatch(handle, -1, pcapCallback, userHandle);
		delay(100); // ms
		//digitalWrite(LED, HIGH);  // On
		
		//digitalWrite(LED, LOW);	  // Off
		//delay(500);
	}
	return 0;
}