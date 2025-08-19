#include <wiringPi.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h> // Contains file controls like O_RDWR
#include <errno.h> // Error integer and strerror() function
#include <termios.h> // Contains POSIX terminal control definitions
#include <unistd.h> // write(), read(), close()
#include <poll.h>
#include <stdio.h>
#include <time.h>
// LED Pin - wiringPi pin 0 is BCM_GPIO 17.
// we have to use BCM numbering when initializing with wiringPiSetupSys
// when choosing a different pin number please use the BCM numbering, also
// update the Property Pages - Build Events - Remote Post-Build Event command
// which uses gpio export for setup for wiringPiSetupSys
#define	LED	17

#define PWR_STATUS_PI 0xef
#define PWR_STATUS_OTHER 0xaf

#define TTY0_GS0_POLL 0x00af


static int pwrStatus = PWR_STATUS_OTHER;

void pcapCallback(u_char* arg_array, const struct pcap_pkthdr* h, const u_char* packet) {
	if (packet[34] == 0x7e && packet[35] == 0xed) {
		digitalWrite(LED, HIGH);  // On
		delay(100); // ms
		digitalWrite(LED, LOW);	  // Off
		pwrStatus = PWR_STATUS_PI;
	}

}
int main() {
// 	const unsigned char beaconPacketData[80] = { 0x0, 0x0, 0x18, 0x0, 0x2b, 0x0, 0x0, 0x0, 0x7b, 0x84, 0xb5, 0x18, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x99, 0x9, 0x0, 0x0, 0xb1, 0x00, 0x80, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x62, 0x45,
// 
// 		//Change these to your own values from "airodump-ng -c 1" every dongle mac address starts with 62:45
// 		0xff, 0xff, 0xff, 0xff,
// 
// 		0x62, 0x45,
// 
// 		//Change these to your own values from "airodump-ng -c 1" every dongle mac address starts with 62:45
// 		0xff, 0xff, 0xff, 0xff,
// 
// 		0xc0, 0xe9, 0x2f, 0x9f, 0xc2, 0x16, 0x0, 0x0, 0x0, 0x0, 0x64, 0x0, 0x31, 0xc6, 0x0, 0x0, 0xdd, 0xc, 0x0, 0x50, 0xf2, 0x11, 0x1, 0x10, 0x0, 0xa1, 0x28, 0x9d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
// 	size_t packet_size = sizeof(beaconPacketData);
// 	pcap_if_t* dev; /* name of the device to use */
// 	char errbuf[PCAP_ERRBUF_SIZE];
// 	struct bpf_program fp_prog;
// 	u_char* userHandle = NULL;
// 	pcap_t* handle = NULL;
// 	/* ask pcap to find a valid device for use to sniff on */
// 	int ret = pcap_init(0, errbuf);
// 	ret = pcap_findalldevs(&dev, errbuf);
// 	handle = pcap_open_live(
// 		"wlan0mon",
// 		BUFSIZ,
// 		1,
// 		1,
// 		errbuf
// 	);
// 	if (handle == NULL) {
// 		fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
// 		return 1;
// 	}
// 	wiringPiSetupSys();
// 
// 	pinMode(LED, OUTPUT);
// 
// 	ret = pcap_compile(handle, &fp_prog, "wlan subtype assoc-req", 1, PCAP_NETMASK_UNKNOWN);
// 	if (ret == -1) {
// 		fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
// 		return 1;
// 	}


	// Open the serial port. Change device path as needed (currently set to an standard FTDI USB-UART cable type device)
	int serial_port = open("/dev/ttyGS0", O_RDWR);
	if (serial_port < 0) {
		printf("Error %i from open: %s\n", errno, strerror(errno));
		return 1;
	}
	int serial = 0;
	int bytes2 = 0;
	printf("Error %i from tcgetattr: %s\n", errno, strerror(errno));
	// Create new termios struct, we call it 'tty' for convention
	struct termios tty;
	struct pollfd  ttyPoll;
	struct stat SerialStat;
	ttyPoll.fd = serial_port;
	// Set up the poll structure
	ttyPoll.events = POLLIN | POLLHUP | POLLOUT; // POLLIN for input, POLLHUP for hangup
	// Read in existing settings, and handle any error
	if (tcgetattr(serial_port, &tty) != 0) {
		printf("Error %i from tcgetattr: %s\n", errno, strerror(errno));
		return 1;
	}
	tty.c_cflag &= ~PARENB; // Clear parity bit, disabling parity (most common)
	tty.c_cflag &= ~CSTOPB; // Clear stop field, only one stop bit used in communication (most common)
	tty.c_cflag &= ~CSIZE; // Clear all bits that set the data size
	tty.c_cflag |= CS8; // 8 bits per byte (most common)
	tty.c_cflag &= ~CRTSCTS; // Disable RTS/CTS hardware flow control (most common)
	tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)

	tty.c_lflag &= ~ICANON;
	tty.c_lflag &= ~ECHO; // Disable echo
	tty.c_lflag &= ~ECHOE; // Disable erasure
	tty.c_lflag &= ~ECHONL; // Disable new-line echo
	tty.c_lflag &= ~ISIG; // Disable interpretation of INTR, QUIT and SUSP
	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
	tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL); // Disable any special handling of received bytes

	tty.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
	tty.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
	// tty.c_oflag &= ~OXTABS; // Prevent conversion of tabs to spaces (NOT PRESENT ON LINUX)
	// tty.c_oflag &= ~ONOEOT; // Prevent removal of C-d chars (0x004) in output (NOT PRESENT ON LINUX)

	tty.c_cc[VTIME] = 10;    // Wait for up to 1s (10 deciseconds), returning as soon as any data is received.
	tty.c_cc[VMIN] = 0;

	// Set in/out baud rate to be 9600
	cfsetispeed(&tty, B9600);
	cfsetospeed(&tty, B9600);

	// Save tty settings, also checking for error
	if (tcsetattr(serial_port, TCSANOW, &tty) != 0) {
		printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
		return 1;
	}

	int re = 0;
	int ret = 0;
	int num_bytes = 0;
	bool isOpen = false;

	signal(SIGHUP, SIG_IGN);
	ret = poll(&ttyPoll, 1, 5000);

	if (ttyPoll.revents & POLLHUP) {
		close(serial_port);
		serial_port = open("/dev/ttyGS0", O_RDWR);
	}
	if (ttyPoll.revents & POLLIN) {
		unsigned short cmd = 0;
		num_bytes = read(serial_port, &cmd, sizeof(cmd));
		if (num_bytes > 0 && cmd == TTY0_GS0_POLL)
		{
			isOpen = true;
		}
	}
	while (true)
	{
		// Read bytes. The behaviour of read() (e.g. does it block?,
		// how long does it block for?) depends on the configuration
		// settings above, specifically VMIN and VTIME
		if ( !isOpen && pwrStatus == PWR_STATUS_OTHER)
		{
			ret = poll(&ttyPoll, 1, 100);
// 			ret = pcap_sendpacket(handle, beaconPacketData, packet_size);
// 			pcap_dispatch(handle, -1, pcapCallback, userHandle);
		}
		else
		{
			ret = poll(&ttyPoll, 1, 500);
		}
		if (ttyPoll.revents & POLLHUP) {
			close(serial_port);
			serial_port = open("/dev/ttyGS0", O_RDWR);
			isOpen = true;
		}

		if (ttyPoll.revents & POLLOUT) {
			write(serial_port, &pwrStatus, sizeof(pwrStatus));
		}
		if (ttyPoll.revents & POLLIN) {
			unsigned short cmd = 0;
			num_bytes = read(serial_port, &cmd, sizeof(cmd));
			if (num_bytes > 0 && cmd == TTY0_GS0_POLL)
			{
				isOpen = true;
			}
			else if (num_bytes == 0)
			{
				isOpen = false;
				pwrStatus = PWR_STATUS_OTHER;
			}
		}
	}


	close(serial_port);
	return 0; // success
};