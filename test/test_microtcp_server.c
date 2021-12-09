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
 * You can use this file to write a test microTCP server.
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../lib/microtcp.h"
#include "../lib/microtcp.c"
int main(int argc, char **argv)
{
    microtcp_sock_t sock;
    int accepted;
    int received;

    socklen_t client_addr_len;
    struct sockaddr_in sin;
    struct sockaddr client_addr;

    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.sd == -1)
    {
        perror("Error at opening microtcp socket.");
        return -1;
    }
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(17800);
    /* Bind to all available network interfaces */
    sin.sin_addr.s_addr = INADDR_ANY;

    if (microtcp_bind(&sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1)
    {
        perror("Error microtcp bind.");
        return -1;
    }

    //sock.state = LISTEN;
    /* Accept a connection from the client */
    client_addr_len = sizeof(struct sockaddr);
    accepted = microtcp_accept(&sock, &client_addr, client_addr_len);
    if (accepted < 0)
    {
        perror("microtcp accept.");
        return -1;
    }

    sock.state = CLOSING_BY_PEER;
    if (microtcp_shutdown(&sock, 0) == -1)
    {
        perror("Error in microtcp shutdown.");
        return -1;
    }
    return 0;
}
