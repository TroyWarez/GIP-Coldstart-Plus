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
#include <termios.h> // Contains POSIX terminal control definitions
#include <unistd.h> // write(), read(), close()
#include <poll.h>
#include <cstdlib>
#include <stdio.h>
#include <time.h>
// LED Pin - wiringPi pin 0 is BCM_GPIO 17.
// we have to use BCM numbering when initializing with wiringPiSetupSys
// when choosing a different pin number please use the BCM numbering, also
// update the Property Pages - Build Events - Remote Post-Build Event command
// which uses gpio export for setup for wiringPiSetupSys

//Start up Script:
// # bash
// airmon-ng start wlan0
// airodump-ng -c 1 wlan0mon & pid = $!
// sleep 5
// kill $pid
// /root/projects/GIP_Coldstart+/bin/ARM64/Release/./GIP_Coldstart+.out
#define	LED	24
#define	PI_LED	27
#define	IR_PWR	17
#define	IR_TX	27
#define TTY0_GS0 "/dev/ttyGS0"
#define PWR_STATUS_PI 0xef
#define PWR_STATUS_OTHER 0xaf
#define CONTROLLER_ARRAY_SIZE 1024

// GIP Commands
#define TTY0_GIP_POLL 0x00af
#define TTY0_GIP_SYNC 0x00b0
#define TTY0_GIP_CLEAR 0x00b1
#define TTY0_GIP_LOCK 0x00b2
#define TTY0_GIP_SYNCED_CONTROLLER_COUNT 0x00b3

static unsigned char AllowControllerArrayList[CONTROLLER_ARRAY_SIZE][6] = { 0x00 }; // TO DO: Populate controller list and save to file.
static int pwrStatus = PWR_STATUS_OTHER;
static int lockStatus = 0;
static int syncMode = 0;
static int controllerCount = 0;
int GetControllerCount()
{
	for( int i = 0; i < CONTROLLER_ARRAY_SIZE; i++ ) {
		if (AllowControllerArrayList[i][0] == 0x00) {
			return i;
		}
	}
}
bool IsControllerAllowed(const u_char* mac) {
	for( int i = 0; i < CONTROLLER_ARRAY_SIZE; i++ ) {
		if (memcmp(&mac[0], &AllowControllerArrayList[i][0], 6) == 0) {
			return true;
		}
		else if (AllowControllerArrayList[i][0] == 0x00) {
			return false;
		}
	}
	return false;
}
int AddController(const u_char* mac) { // Return new controller count
	for (int i = 0; i < CONTROLLER_ARRAY_SIZE; i++) {
		if (AllowControllerArrayList[i][0] == 0x00) {
			memcpy(&AllowControllerArrayList[i][0], &mac[0], 6);
			return GetControllerCount();
		}
	}
}
void pcapCallback(u_char* arg_array, const struct pcap_pkthdr* h, const u_char* packet) {
	if ( h->caplen >= 40) {
		if ( packet[34] == 0x7e && packet[35] == 0xed && syncMode && !IsControllerAllowed(&packet[34])) {
			syncMode = false;
			controllerCount = AddController(&packet[34]);

		}
		else if(!lockStatus && pwrStatus == PWR_STATUS_OTHER && !syncMode && IsControllerAllowed(&packet[34])) {
			pwrStatus = PWR_STATUS_PI;
			digitalWrite(LED, HIGH);  // On
			delay(100); // ms
			digitalWrite(LED, LOW);	  // Off
		}

	}

}
int main() {
	int fd = -1;
	wiringPiSetupSys();
	pinMode(LED, OUTPUT);
	pinMode(IR_TX, OUTPUT);
	pinMode(IR_PWR, OUTPUT);

	const unsigned char beaconPacketData[80] = { 0x0, 0x0, 0x18, 0x0, 0x2b, 0x0, 0x0, 0x0, 0x7b, 0x84, 0xb5, 0x18, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x99, 0x9, 0x0, 0x0, 0xb1, 0x00, 0x80, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x62, 0x45, 0xff, 0xff, 0xff, 0xff,0x62, 0x45,0xff, 0xff, 0xff, 0xff,
		0xc0, 0xe9, 0x2f, 0x9f, 0xc2, 0x16, 0x0, 0x0, 0x0, 0x0, 0x64, 0x0, 0x31, 0xc6, 0x0, 0x0, 0xdd, 0xc, 0x0, 0x50, 0xf2, 0x11, 0x1, 0x10, 0x0, 0xa1, 0x28, 0x9d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
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
	while (handle == NULL) {
		handle = pcap_open_live(
			"wlan0mon",
			BUFSIZ,
			1,
			1,
			errbuf
		);
	}
	wiringPiSetupSys();

	pinMode(LED, OUTPUT);
	pinMode(IR_PWR, OUTPUT);
	digitalWrite(IR_PWR, HIGH);  // On
	pinMode(IR_TX, OUTPUT);
	digitalWrite(IR_PWR, HIGH);  // On

	// Open the serial port. Change device path as needed (currently set to an standard FTDI USB-UART cable type device)
	int serial_port = open(TTY0_GS0, O_RDWR);
	if (serial_port < 0) {
		//printf("Error %i from open: %s\n", errno, strerror(errno));
		return 1;
	}
	int serial = 0;
	int bytes2 = 0;
	// Create new termios struct, we call it 'tty' for convention
	struct termios tty;
	struct pollfd  ttyPoll;
	struct stat SerialStat;
	ttyPoll.fd = serial_port;
	// Set up the poll structure
	ttyPoll.events = POLLIN | POLLHUP | POLLOUT; // POLLIN for input, POLLHUP for hangup
	// Read in existing settings, and handle any error
	if (tcgetattr(serial_port, &tty) != 0) {
		//printf("Error %i from tcgetattr: %s\n", errno, strerror(errno));
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
		//printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
		return 1;
	}

	int re = 0;
	int num_bytes = 0;
	bool isOpen = false;

	signal(SIGHUP, SIG_IGN);
	ret = poll(&ttyPoll, 1, 5000);

	if (ttyPoll.revents & POLLHUP) {
		close(serial_port);
		serial_port = open(TTY0_GS0, O_RDWR);
	}
	if (ttyPoll.revents & POLLIN) {
		unsigned short cmd = 0;
		num_bytes = read(serial_port, &cmd, sizeof(cmd));
		if (num_bytes > 0)
		{
			isOpen = true;
			switch (cmd)
			{
			case TTY0_GIP_POLL:
			{
				lockStatus = 0;
				break;
			}

			case TTY0_GIP_SYNC:
			{
				syncMode = true;
				break;
			}
			case TTY0_GIP_SYNCED_CONTROLLER_COUNT:
			{
				controllerCount = GetControllerCount();
				write(serial_port, &controllerCount, sizeof(controllerCount));
				break;
			}
			case TTY0_GIP_CLEAR:
			{
				lockStatus = 0;
				memset(AllowControllerArrayList, 0, sizeof(AllowControllerArrayList));
				break;
			}
			case TTY0_GIP_LOCK:
			{
				lockStatus = 1;
				break;
			}
			default: 
			{
				isOpen = false;
				break;
			}
			}

		}
	}

	unsigned short cmd = 0;
	while (true)
	{
		// Read bytes. The behaviour of read() (e.g. does it block?,
		// how long does it block for?) depends on the configuration
		// settings above, specifically VMIN and VTIME
		if ( !isOpen && pwrStatus == PWR_STATUS_OTHER)
		{
			if (handle)
			{
		ret = pcap_sendpacket(handle, beaconPacketData, packet_size);
		pcap_dispatch(handle, -1, pcapCallback, userHandle);
			}
			ret = poll(&ttyPoll, 1, 100);
		}
		else
		{
			ret = poll(&ttyPoll, 1, 500);
		}
		if (ttyPoll.revents & POLLHUP) {
			close(serial_port);
			serial_port = open(TTY0_GS0, O_RDWR);
		}

		if (ttyPoll.revents & POLLOUT) {
			write(serial_port, &pwrStatus, sizeof(pwrStatus));
		}
		if (ttyPoll.revents & POLLIN) {
			num_bytes = read(serial_port, &cmd, sizeof(cmd));
			if (num_bytes > 0 && !isOpen)
			{
				isOpen = true;
				pwrStatus = PWR_STATUS_OTHER;
				switch (cmd)
				{
				case TTY0_GIP_POLL:
				{
					break;
				}
				case TTY0_GIP_SYNC:
				{
					digitalWrite(LED, HIGH);  // On
					delay(100); // ms
					digitalWrite(LED, LOW);	  // Off
					break;
				}
				{
					break;
				}
				} 
			}
		}
		else if (ttyPoll.revents == 0 && isOpen) {
			ret = poll(&ttyPoll, 1, 3000);
			if (!(ttyPoll.revents & POLLIN)) {
				isOpen = false;
			}

		}
	}


	close(serial_port);
	return 0; // success
};