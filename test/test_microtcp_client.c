/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>
//#include <sys/socket.h>
#include <netinet/in.h>
#include "../lib/microtcp.c"
#include <arpa/inet.h>

#include "../lib/microtcp.h"

int main(int argc, char **argv)
{
    microtcp_sock_t sock;
    socklen_t client_addr_len;
    struct sockaddr_in sin;
    struct sockaddr *client_addr;

    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.sd == -1)
    {
        perror("Error at opening microtcp socket.");
        return -1;
    }
    //printf("CLIENT after socket(seq,ack):%d,%d\n", sock.seq_number, sock.ack_number);
    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    /*Port that server listens at */
    sin.sin_port = htons(17800);
    /* The server's IP*/
    sin.sin_addr.s_addr = inet_addr("147.52.19.79"); //we need to change it accordingly the command is:    curl ifconfig.me
    sock.address = sin;
    //sock.address_len = sizeof(struct sockaddr_in);

    if (microtcp_connect(&sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1)
    {
        perror("Error in microtcp connect.");
        return -1;
    }
    //printf("before shutdown in client\n");
    if (microtcp_shutdown(&sock, 0) == -1)
    {
        perror("Error in microtcp shutdown.");
        return -1;
    }
    //printf("after shutdown in client.\n");
    return 0;
}
