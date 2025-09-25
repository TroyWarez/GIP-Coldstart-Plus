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
// /boot/./GIP_Coldstart+.out
#define	LED	24
#define	PI_LED	27
#define TTY0_GS0 "/dev/ttyAMA0"
#define PWR_STATUS_PI 0xef
#define PWR_STATUS_OTHER 0xaf

#define CONTROLLER_ARRAY_SIZE 1024
#define CONTROLLER_MAC_ADDRESS_SIZE 6

// GIP Commands
#define TTY0_GIP_POLL 0xaf
#define TTY0_GIP_SYNC 0xb0
#define TTY0_GIP_CLEAR_ALL 0xb1
#define TTY0_GIP_LOCK 0xb2
#define TTY0_GIP_GET_PWR_STATUS 0xb3
#define TTY0_GIP_CLEAR_ALL_NEXT_SYNCED_CONTROLLER 0xb4

static unsigned char AllowControllerArrayList[CONTROLLER_ARRAY_SIZE][CONTROLLER_MAC_ADDRESS_SIZE] = { 0x00 }; // TO DO: Populate controller list and save to file.
static int pwrStatus = PWR_STATUS_OTHER;
static int lockStatus = false;
static int syncMode = false;
static int clearMode = false;
static int controllerCount = false;
int GetControllerCount()
{
	for( int i = 0; i < CONTROLLER_ARRAY_SIZE; i++ ) {
		if (AllowControllerArrayList[i][0] == 0x00) {
			return i;
		}
	}
	return 0;
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
			break;
		}
	}
	return GetControllerCount();
}
int RemoveController(const u_char* mac) { // Return new controller count
	for (int i = 0; i < CONTROLLER_ARRAY_SIZE; i++) {
		if (memcmp(&mac[0], &AllowControllerArrayList[i][0], 6) == 0 && (i + 1 < CONTROLLER_ARRAY_SIZE) && AllowControllerArrayList[i + 1][0] != 0){
			memcpy(&AllowControllerArrayList[i][0], &AllowControllerArrayList[i + 1][0], (sizeof(AllowControllerArrayList) - ((i + 1) * 6)));
			break;
		}
		else if (AllowControllerArrayList[i][0] == 0x00) {
			break;
		}
	}
	return GetControllerCount();
}
void saveControllerListToFile()
{
	FILE* fp;
	fp = fopen("/boot/allowed_controllers.txt", "w");
	if (fp != NULL) {
		for (int i = 0; i < CONTROLLER_ARRAY_SIZE; i++) {
			if (AllowControllerArrayList[i][0] != 0x00) {
				fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x\n", AllowControllerArrayList[i][0], AllowControllerArrayList[i][1], AllowControllerArrayList[i][2], AllowControllerArrayList[i][3], AllowControllerArrayList[i][4], AllowControllerArrayList[i][5]);
			}
			else {
				break;
			}
		}
		fclose(fp);
	}
}
void loadControllerListFromFile()
{
	FILE* fp;
	fp = fopen("/boot/allowed_controllers.txt", "r");
	if (fp != NULL) {
		memset(&AllowControllerArrayList, 0, sizeof(AllowControllerArrayList));
		char line[18];
		int index = 0;
		while (fgets(line, sizeof(line), fp) != NULL && index < CONTROLLER_ARRAY_SIZE) {
			unsigned int mac[6] = { 0 };
			if (sscanf(line, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
				for (int j = 0; j < 6; j++) {
					AllowControllerArrayList[index][j] = (unsigned char)mac[j];
				}
				index++;
			}
		}
		fclose(fp);
		controllerCount = GetControllerCount();
	}
	else
	{
		memset(&AllowControllerArrayList, 0, sizeof(AllowControllerArrayList));
	}
}
void pcapCallback(u_char* arg_array, const struct pcap_pkthdr* h, const u_char* packet) {
	if ( h->caplen >= 40) {
		if (packet[34] == 0x7e && packet[35] == 0xed)
		{
			syncMode = true; // Debug, remove me
			if (syncMode && !clearMode) {
				syncMode = false;
				if (!IsControllerAllowed(&packet[34]))
				{
					controllerCount = AddController(&packet[34]);
					saveControllerListToFile();
				}
			}
			else if (clearMode)
			{
				clearMode = false;
				if (IsControllerAllowed(&packet[34]))
				{
					controllerCount = RemoveController(&packet[34]);
					saveControllerListToFile();
				}
			}
			else if (!lockStatus && pwrStatus == PWR_STATUS_OTHER && IsControllerAllowed(&packet[34])) {
				pwrStatus = PWR_STATUS_PI;
// 				digitalWrite(LED, HIGH);  // On
// 				delay(100); // ms
// 				digitalWrite(LED, LOW);	  // Off
			}
		}

	}

}
int main() {
	//printf("GIP Coldstart+ started!\n");
	wiringPiSetupSys();
	pinMode(LED, OUTPUT);
	pcap_if_t* dev; /* name of the device to use */
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char* userHandle = NULL;
	pcap_t* handle = NULL;
	/* ask pcap to find a valid device for use to sniff on */
	pcap_init(0, errbuf);
	pcap_findalldevs(&dev, errbuf);
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

	// Open the serial port. Change device path as needed (currently set to an standard FTDI USB-UART cable type device)

	const unsigned char beaconPacketData[80] = { 0x0, 0x0, 0x18, 0x0, 0x2b, 0x0, 0x0, 0x0, 0x7b, 0x84, 0xb5, 0x18, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x99, 0x9, 0x0, 0x0, 0xb1, 0x00, 0x80, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x62, 0x45, 0xff, 0xff, 0xff, 0xff,0x62, 0x45,0xff, 0xff, 0xff, 0xff,
	0xc0, 0xe9, 0x2f, 0x9f, 0xc2, 0x16, 0x0, 0x0, 0x0, 0x0, 0x64, 0x0, 0x31, 0xc6, 0x0, 0x0, 0xdd, 0xc, 0x0, 0x50, 0xf2, 0x11, 0x1, 0x10, 0x0, 0xa1, 0x28, 0x9d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	int packet_size = sizeof(beaconPacketData);
	int serial_port = open(TTY0_GS0, O_RDWR);
	if (serial_port < 0) {
		//printf("Error %i from open: %s\n", errno, strerror(errno));
		return 1;
	}
	// Create new termios struct, we call it 'tty' for convention
	struct termios tty;
	struct pollfd  ttyPoll;
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
	int cmd = 0;
	// Save tty settings, also checking for error
	if (tcsetattr(serial_port, TCSANOW, &tty) != 0) {
		//printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
		return 1;
	}

	ssize_t num_bytes = 0;
	bool isOpen = false;
	loadControllerListFromFile();

	signal(SIGHUP, SIG_IGN);
	poll(&ttyPoll, 1, 5000);

	if (ttyPoll.revents & POLLHUP) {
		close(serial_port);
		serial_port = open(TTY0_GS0, O_RDWR);
	}
	if (ttyPoll.revents & POLLIN) {
		num_bytes = read(serial_port, &cmd, sizeof(cmd));
		if (num_bytes == sizeof(cmd))
		{
			isOpen = true;
			switch (cmd)
			{
			case TTY0_GIP_POLL:
			{
				lockStatus = false;
				syncMode = false;
				clearMode = false;
				controllerCount = GetControllerCount();
				break;
			}

			case TTY0_GIP_SYNC: //Untested
			{
				lockStatus = true;
				syncMode = true;
				clearMode = false;
				controllerCount = GetControllerCount();
				break;
			}
			case TTY0_GIP_GET_PWR_STATUS: //Untested
			{
				controllerCount = GetControllerCount();
				write(serial_port, &controllerCount, sizeof(controllerCount));
				break;
			}
			case TTY0_GIP_CLEAR_ALL: //Untested
			{
				lockStatus = true;
				syncMode = false;
				clearMode = false;
				remove("/boot/allowed_controllers.txt");
				memset(AllowControllerArrayList, 0, sizeof(AllowControllerArrayList));
				controllerCount = GetControllerCount();
				break;
			}
			case TTY0_GIP_CLEAR_ALL_NEXT_SYNCED_CONTROLLER: //Untested
			{
				lockStatus = true;
				clearMode = true;
				break;
			}
			case TTY0_GIP_LOCK: //Untested
			{
				lockStatus = true;
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

	while (true)
	{
		// Read bytes. The behaviour of read() (e.g. does it block?,
		// how long does it block for?) depends on the configuration
		// settings above, specifically VMIN and VTIME
		if ( !isOpen && pwrStatus == PWR_STATUS_OTHER)
		{
			if (handle)
			{
				pcap_sendpacket(handle, beaconPacketData, packet_size);
				pcap_dispatch(handle, -1, pcapCallback, userHandle);
			}
			poll(&ttyPoll, 1, 100);
		}
		else
		{
			poll(&ttyPoll, 1, 500);
		}
		if (ttyPoll.revents & POLLHUP) {
			close(serial_port);
			serial_port = open(TTY0_GS0, O_RDWR);
		}
		if (ttyPoll.revents & POLLIN) {
			num_bytes = read(serial_port, &cmd, sizeof(cmd));
			if (num_bytes > 0)
			{
				isOpen = true;
				switch (cmd)
				{
				case TTY0_GIP_POLL:
				{
					lockStatus = false;
					syncMode = false;
					clearMode = false;
					controllerCount = GetControllerCount();
					break;
				}

				case TTY0_GIP_SYNC:
				{
					lockStatus = true;
					syncMode = true;
					clearMode = false;
					controllerCount = GetControllerCount();
					break;
				}
				case TTY0_GIP_GET_PWR_STATUS: //Untested
				{
					lockStatus = false;
					syncMode = false;
					clearMode = false;
					controllerCount = GetControllerCount();
					break;
				}
				case TTY0_GIP_CLEAR_ALL: //Untested
				{
					lockStatus = true;
					syncMode = false;
					clearMode = false;
					remove("/boot/allowed_controllers.txt");
					memset(AllowControllerArrayList, 0, sizeof(AllowControllerArrayList));
					controllerCount = GetControllerCount();
					break;
				}
				case TTY0_GIP_CLEAR_ALL_NEXT_SYNCED_CONTROLLER: //Untested
				{
					lockStatus = true;
					clearMode = true;
					break;
				}
				case TTY0_GIP_LOCK: //Untested
				{
					lockStatus = true;
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
		else if (ttyPoll.revents == 0 && isOpen) {
			poll(&ttyPoll, 1, 3000);
			if (!(ttyPoll.revents & POLLIN)) {
				isOpen = false;
			}

		}
		if (ttyPoll.revents & POLLOUT) {
			if (cmd == TTY0_GIP_POLL)
			{
				write(serial_port, &controllerCount, sizeof(controllerCount));
			}
			else
			{
				write(serial_port, &pwrStatus, sizeof(pwrStatus));
			}

		}
	}


	close(serial_port);
	return 0; // success
};