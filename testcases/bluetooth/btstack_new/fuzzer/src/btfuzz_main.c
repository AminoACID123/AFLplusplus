#include <assert.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <aio.h>

#include "btfuzz.h"
#include "btfuzz_state.h"
#include "common/random.h"

#define MAX_BUFFER_SIZE 1024*1024*4
uint8_t data[MAX_BUFFER_SIZE];

void send_init_packet(int fd)
{
	uint8_t buf[1024];
	/* Reset */
    uint8_t packet1[] = {0x0E, 0x04, 0x01, 0x03, 0x0c, 0x00};
    /* Read Local Version */
    uint8_t packet2[] = {0x0E, 0x0C, 0x01, 0x01, 0x10, 0x00, 0x0C, 0xFF, 0xFF, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF};
    /* Read Local Name */
    uint8_t packet3[254] = {0x0E, 0xFC, 0x01, 0x14, 0x0c, 0x00, 'F', 'U', 'Z', 'Z'};
    // Read Local Commands
    uint8_t packet4[70] = {0x0E, 0x44, 0x01, 0x02, 0x10, 0x00};
    memset(packet4 + 6, 0xFF, 64);
    // Read BD_ADDR
    uint8_t packet5[] = {0x0E, 0x0a, 0x01, 0x09, 0x10, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    // Read Buffer Size
    uint8_t packet6[] = {0x0E, 0x0B, 0x01, 0x05, 0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Read Local Features
    uint8_t packet7[] = {0x0E, 0x0c, 0x01, 0x03, 0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Set Event Mask
    uint8_t packet8[] = {0x0E, 0x04, 0x01, 0x01, 0x0c, 0x00};
    // Set Event Mask Page2
    uint8_t packet9[] = {0x0E, 0x04, 0x01, 0x63, 0x0c, 0x00};
    // LE Read Buffer Size V2
    uint8_t packet10[] = {0x0E, 0x0a, 0x01, 0x60, 0x20, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Write LE Host Supported
    uint8_t packet11[] = {0x0E, 0x04, 0x01, 0x6d, 0x0c, 0x00};
    // LE Set Event Mask
    uint8_t packet12[] = {0x0E, 0x04, 0x01, 0x01, 0x20, 0x00};
    // LE Read Max Data Length
    uint8_t packet13[] = {0x0E, 0x0c, 0x01, 0x2f, 0x20, 0x00, 0xFB, 0x00, 0x90, 0x42, 0xFB, 0x00, 0x90, 0x42};
    // LE Write Default Data Length
    uint8_t packet14[] = {0x0E, 0x04, 0x01, 0x24, 0x20, 0x00};
    // LE Read Accept List Size
    uint8_t packet15[] = {0x0E, 0x05, 0x01, 0x0f, 0x20, 0x00, 0xff};
    // LE Read Max Adv Data Len
    uint8_t packet16[] = {0x0E, 0x06, 0x01, 0x3a, 0x20, 0x00, 0x72, 0x06};
    // LE Set Ext Scan Params
    uint8_t packet17[] = {0x0E, 0x04, 0x01, 0x41, 0x20, 0x00};
    // LE Rand
    uint8_t packet18[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0xB8, 0x4E, 0x75, 0xC7, 0xE2, 0xBE, 0x8E, 0xAA};
    // LE Rand
    uint8_t packet19[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0xC6, 0x28, 0x81, 0xA5, 0xB9, 0xB1, 0x59, 0xFE};
    // LE Rand
    uint8_t packet20[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0x39, 0x77, 0x84, 0x1C, 0x29, 0x33, 0xEF, 0xF6};
    // LE Rand
    uint8_t packet21[] = {0x0E, 0x0c, 0x01, 0x18, 0x20, 0x00, 0x08, 0x4A, 0x6F, 0x0D, 0x19, 0xE4, 0x23, 0x0A};
    // LE Set Resolve Enable
    uint8_t packet22[] = {0x0E, 0x04, 0x01, 0x2d, 0x20, 0x00};
    // LE Read Resolve List Size
    uint8_t packet23[] = {0x0E, 0x05, 0x01, 0x2a, 0x20, 0x00, 0xFF};
    // LE Clear Resolve List
    uint8_t packet24[] = {0x0E, 0x04, 0x01, 0x29, 0x20, 0x00};
	uint8_t* packets[] = {
		packet1, packet2,packet3,packet4, packet5,packet6,packet7, packet8,
		packet9, packet10,packet11,packet12, packet13,packet14,packet15, packet16,
		packet17, packet18,packet19,packet20, packet21,packet22,packet23, packet24,
	};


	for(int i=0;i<24;i++)
	{
		int len = read(fd, buf, 1024);
		if(len>0){
			printf("received %d bytes: ", len);
			for (int i=0;i<len;i++)
				printf("%02X ", buf[i]);
			printf("\n");
			struct iovec iov[2];
			uint8_t event = 4;
			iov[0].iov_base = &event;
			iov[0].iov_len = 1;
			iov[1].iov_base = packets[i];
			iov[1].iov_len = packets[i][1] + 2;
			writev(fd, iov, 2);
            printf("Sent packet %d\n", i);
		}
	}
	int len = read(fd, buf, 1024);
			printf("received %d bytes: ", len);
			for (int i=0;i<len;i++)
				printf("%02X ", buf[i]);
			printf("\n");
}

void run()
{
    while (1)
    {
        struct timeval tv;
        fd_set fd_set_read;
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        FD_SET(hci_sock_fd, &fd_set_read);

        int n = select(hci_sock_fd + 1, &fd_set_read, NULL, NULL, &tv);
        if (n > 0){
            int len = read(hci_sock_fd, data, MAX_BUFFER_SIZE);
            btfuzz_packet_handler(data, len);
        }
        else if (n == 0){
            btfuzz_step_one();
        }else
            assert(false && "Select error");
    }
    
}


static void signal_callback(int signum, void *user_data)
{
	// switch (signum) {
	// case SIGINT:
	// case SIGTERM:
	// 	mainloop_quit();
	// 	break;
	// }
}

int main(int argc, char** argv)
{
	if(remove(hci_sock_path) == -1 && errno != ENOENT)
	{
		perror("Error deleting existing socket");
		exit(-1);
	}

    rand_init();

	int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strcpy(sock_addr.sun_path, hci_sock_path);
	if(bind(sock_fd, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_un)))
	{
		perror("error binding socket");
		return -1;
	}
	listen(sock_fd, 5);
	hci_sock_fd = accept(sock_fd, 0, 0);

    btfuzz = (btfuzz_state_t*)calloc(1, sizeof(btfuzz_state_t));

    run();
    return 0;

}
