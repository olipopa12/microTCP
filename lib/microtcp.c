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

#include "microtcp.h"
#include "../utils/crc32.h"
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
microtcp_sock_t
microtcp_socket(int domain, int type, int protocol)
{
	/* Your code here */
	microtcp_sock_t msocket;
	int sock = socket(domain, type, protocol);
	msocket.sd = sock;
	if (sock == -1)
	{
		msocket.state = INVALID;
		perror("Error in microtcp_socket.");
	}
	else
	{
		msocket.state = UNKNOWN;
		msocket.init_win_size = MICROTCP_WIN_SIZE;
		msocket.curr_win_size = MICROTCP_WIN_SIZE;
		msocket.ssthresh = MICROTCP_INIT_SSTHRESH;
		msocket.cwnd = MICROTCP_INIT_CWND;
	}
	return msocket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
				  socklen_t address_len)
{
	/* Your code here */
	assert(address != NULL);
	int bind_result = bind(socket->sd, address, address_len);
	return bind_result;
}

//client->connect,server->accept
static uint32_t init_seq ;

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
					 socklen_t address_len)
{
	/* Your code here */
	microtcp_header_t send_header;
	int N;
	uint32_t checkSum;
	uint8_t buffer[MICROTCP_RECVBUF_LEN];
	microtcp_header_t check_header;
	uint32_t tmpcheck;
	microtcp_header_t *recv_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));
	uint16_t SYN = syn_fix(1, 0), ACK = ack_fix(1, 0), SYN_ACK = ack_fix(1, SYN);

	if (!recv_header) //check malloc
	{
		perror("Error in microtcp_connect in malloc in recv_header.");
		return -1;
	}

	srand(time(NULL));
	N = (rand() % 100);
	memset(&send_header, 0, sizeof(microtcp_header_t));
	send_header.seq_number = htonl(N); //seq=N random
	send_header.ack_number = 0;		   //ack=0
	send_header.control = htons(SYN);  //SYN

	memset(buffer, 0, MICROTCP_RECVBUF_LEN);
	/*while (i < MICROTCP_RECVBUF_LEN)
		buffer[i++] = 0;*/
	memcpy(buffer, &send_header, sizeof(microtcp_header_t));
	//printf("checksum before first send of connect:%d\n", crc32(buffer, MICROTCP_RECVBUF_LEN));
	send_header.checksum = htonl(crc32(buffer, MICROTCP_RECVBUF_LEN));
	//printf("checksum before first send of connect:%d\n", send_header.checksum);
	//printf("Before first send of connect (seq,ack) :%d,%d\n", (send_header.seq_number), send_header.ack_number);
	//send the first packet(SYN)
	if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, address, address_len) == -1)
	{
		perror("Error in microtcp_connect unable to send the first packet (SYN).");
		return -1;
	}
	//we sent the first packet and we wait for response
	if (recvfrom(socket->sd, recv_header, sizeof(microtcp_header_t), 0, address, &address_len) == -1)
	{
		perror("Error in microtcp_connect unable to receive the second packet(SYN_ACK).");
		return -1;
	}
	//	printf("after first receive of connect (seq,ack) :%d,%d\n", ntohl(recv_header->seq_number), ntohl(recv_header->ack_number));
	tmpcheck = ntohl(recv_header->checksum);
	recv_header->checksum = 0;
	memset(buffer, 0, MICROTCP_RECVBUF_LEN);
	memcpy(buffer, recv_header, sizeof(microtcp_header_t));
	if (crc32(buffer, sizeof(buffer)) != tmpcheck)
	{ //error on checksum
		perror("Error in microtcp_connect in checksum at the second packet(SYN_ACK).");
		return -1;
	}
	//we received the first packet
	//is it a SYN_ACK?
	if (ntohs(recv_header->control) != SYN_ACK)
	{
		perror("Error in microtcp_connect the second packet is not SYN_ACK.");
		return -1;
	}
	//socket->curr_win_size = ntohl(recv_header->window);
	send_header.seq_number = ntohl(recv_header->ack_number);	 //seq=ack_server
	send_header.ack_number = ntohl(recv_header->seq_number + 1); //ack=seq_server+1
	send_header.control = htons(ACK);
	send_header.checksum = 0;
	send_header.window = htons(socket->curr_win_size); //an ACK packet

	memset(buffer, 0, MICROTCP_RECVBUF_LEN);
	memcpy(buffer, &send_header, sizeof(send_header));
	send_header.checksum = htonl(crc32(buffer, sizeof(buffer)));

	//printf("Before second send of connect (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));
	//try to send the third packet(ACK)
	if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, address, address_len) == -1)
	{
		perror("Error in microtcp_connect unable to send the third packet(ACK).");
		return -1;
	}
	//we sent the third packet
	//connection is established now
	socket->state = ESTABLISHED;
	socket->seq_number = ntohl(send_header.seq_number);
	socket->ack_number = ntohl(send_header.ack_number);
	//printf("after enstablished in connect (seq,ack) :%d,%d\n", socket->seq_number, socket->ack_number);
	init_seq = socket->seq_number;
	return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
					socklen_t address_len)
{
	/* Your code here */
	uint8_t buffer[MICROTCP_RECVBUF_LEN];
	microtcp_header_t send_header;
	microtcp_header_t check_head_pack;
	uint32_t tmpcheck;
	int M;
	uint16_t SYN = syn_fix(1, 0), ACK = ack_fix(1, 0), SYN_ACK = ack_fix(1, SYN);
	microtcp_header_t *recv_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));

	assert(address != NULL);
	socket->state = LISTEN;
	if (!recv_header) //check malloc
	{
		perror("Error in microtcp_accept in malloc in recv_header.");
		return -1;
	}
	//try to receive the first packet
	if (recvfrom(socket->sd, recv_header, sizeof(microtcp_header_t), 0, address, &address_len) == -1)
	{
		perror("Error in  microtcp_accept unable to receive the first packet(SYN).");
		return -1;
	}
	//	printf("after first receive of accept (seq,ack) :%d,%d\n", ntohl(recv_header->seq_number), ntohl(recv_header->ack_number));
	//printf("checksum after first rreceive of accept:%d\n", recv_header->checksum);
	tmpcheck = ntohl(recv_header->checksum);
	recv_header->checksum = 0;
	memset(buffer, 0, MICROTCP_RECVBUF_LEN);
	memcpy(buffer, recv_header, sizeof(microtcp_header_t));
	//printf("tmpcheck,check:%d,%d\n", tmpcheck, crc32(buffer, MICROTCP_RECVBUF_LEN));
	if (crc32(buffer, MICROTCP_RECVBUF_LEN) != tmpcheck)
	{ //error on checksum
		perror("Error in  microtcp_accept in checksum at the first packet(SYN).");
		return -1;
	}
	//we received the first packet
	//is it a SYN?
	if (ntohs(recv_header->control) != SYN)
	{
		perror("Error in microtcp_accept the first packet is not SYN.");
		return -1;
	}

	srand(time(NULL));
	M = (rand() % (1000 - 100 + 1)) + 100;					//(rand()% (up-low+1))+lowe
	send_header.seq_number = htonl(M);						//seq=M                           //seq=M
	send_header.ack_number = (recv_header->seq_number + 1); //ack=seq_client+1=N+1
	send_header.control = htons(SYN_ACK);					//an SYN_ACK packet
	send_header.checksum = 0;
	memset(buffer, 0, MICROTCP_RECVBUF_LEN);
	memcpy(buffer, &send_header, sizeof(microtcp_header_t));
	send_header.checksum = htonl(crc32(buffer, sizeof(buffer)));

	//printf("Before first send of accept (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));
	//try to send the second packet(SYN_ACK)
	if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, address, address_len) == -1)
	{
		perror("Error in microtcp_accept unable to send the second packet(SYN_ACK).");
		return -1;
	}
	//we sent the second packet and we wait for response
	//try to receive the third packet(ACK)
	if (recvfrom(socket->sd, recv_header, sizeof(microtcp_header_t), 0, address, &address_len) == -1)
	{
		perror("Error in microtcp_accept unable to receive the third packet(ACK).");
		return -1;
	}
	//	printf("after second receive of accept (seq,ack) :%d,%d\n", ntohl(recv_header->seq_number), ntohl(recv_header->ack_number));
	tmpcheck = ntohl(recv_header->checksum);
	recv_header->checksum = 0;
	memset(buffer, 0, MICROTCP_RECVBUF_LEN);
	memcpy(buffer, recv_header, sizeof(microtcp_header_t));
	if (crc32(buffer, sizeof(buffer)) != tmpcheck)
	{ //error on checksum
		perror("Error in  microtcp_accept in checksum at the third packet(ACK).");
		return -1;
	}

	//we received the third packet
	//is it an ACK?
	if (ntohs(recv_header->control) != ACK)
	{
		perror("Error in microtcp_accept the third packet is not ACK.");
		return -1;
	}

	if (ntohl(recv_header->seq_number) != (send_header.ack_number) ||
		ntohl(recv_header->ack_number) != (send_header.seq_number + 1))
	{
		perror("Error in microtcp_accept at the third packet(ACK) we have wrong numbers.");
		return -1;
	}
	//connection is established now
	//printf("current win size:%d\n", socket->curr_win_size);
	socket->seq_number = ntohl(recv_header->ack_number);
	socket->ack_number = ntohl(recv_header->seq_number);
	socket->state = ESTABLISHED;
	//printf("after enstablished in accept (seq,ack) :%d,%d\n", socket->seq_number, socket->ack_number);
	return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
	/* Your code here */
	microtcp_header_t send_header;
	int Y;
	struct sockaddr *addr;
	ssize_t tmpcheck;
	uint8_t buffer[MICROTCP_RECVBUF_LEN];
	uint16_t FIN = fin_fix(1, 0), ACK = ack_fix(1, 0), FIN_ACK = ack_fix(1, FIN);
	socklen_t len = sizeof(socket->address);
	microtcp_header_t *recv_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));
	addr = (struct sockaddr *)&socket->address;

	if (!recv_header) //check malloc
	{
		perror("Error in microtcp_shutdown in malloc in recv_header.");
		return -1;
	}

	if (socket->state == CLOSING_BY_PEER)
	{

		//we received the first packet
		memset(&send_header, 0, sizeof(microtcp_header_t));
		send_header.ack_number = htonl(socket->ack_number);
		send_header.seq_number = htonl(socket->seq_number);
		send_header.control = htons(ACK);
		send_header.window = htonl(socket->curr_win_size);

		memset(buffer, 0, MICROTCP_RECVBUF_LEN);
		memcpy(buffer, &send_header, sizeof(microtcp_header_t));
		send_header.checksum = htonl(crc32(buffer, sizeof(buffer)));
		//try to send the second packet(ACK)
		//printf("Before first send of shutdown in server (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));
		if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, addr, len) < 0)
		{
			perror("Error in microtcp_shutdown unable to send the second packet(ACK).");
			return -1;
		}

		send_header.ack_number = htonl(socket->ack_number);
		send_header.seq_number = htonl(socket->seq_number + 1);
		send_header.control = htons(FIN_ACK);
		send_header.window = htonl(socket->curr_win_size);
		send_header.checksum = 0;
		memset(buffer, 0, MICROTCP_RECVBUF_LEN);
		memcpy(buffer, &send_header, sizeof(microtcp_header_t));
		send_header.checksum = htonl(crc32(buffer, sizeof(buffer)));
		//printf("Before second send of shutdown in server(seq,ack):%d,%d\n", (send_header.seq_number), (send_header.ack_number));
		//try to send the third packet(FIN_ACK)
		if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, addr, len) < 0)
		{
			perror("Error in microtcp_shutdown unable to send the third packet(FIN_ACK).");
			return -1;
		}
		//we sent the third packet and we wait for response
		//try to receive the fourth packet(ACK)
		if (recvfrom(socket->sd, recv_header, sizeof(microtcp_header_t), 0, addr, &len) == -1)
		{
			perror("Error in microtcp_shutdown unable to receive the fourth packet(ACK).");
			return -1;
		}
		//		printf("after second receive in server (seq,ack) :%d,%d\n", ntohl(recv_header->seq_number), ntohl(recv_header->ack_number));
		tmpcheck = ntohl(recv_header->checksum);
		recv_header->checksum = 0;
		memset(buffer, 0, MICROTCP_RECVBUF_LEN);
		memcpy(buffer, recv_header, sizeof(microtcp_header_t));
		if (crc32(buffer, sizeof(buffer)) != tmpcheck)
		{ //error on checksum
			perror("Error in  microtcp_shutdown in checksum at the fourth packet(ACK).");
			return -1;
		}
		//we received the fourth packet
		//is it an ACK?
		if (ntohs(recv_header->control) != ACK)
		{
			perror("Error in microtcp_shutdown the fourth packet is not ACK.");
			return -1;
		}
		if (ntohl(recv_header->seq_number) != (send_header.ack_number) ||
			ntohl(recv_header->ack_number) != (send_header.seq_number) + 1)
		{
			perror("Error in microtcp_shutdown at the fourth packet(ACK) we have wrong numbers.");
			return -1;
		}
	}
	else
	{
		//in client
		//printf("in client now.\n");
		memset(&send_header, 0, sizeof(microtcp_header_t));
		send_header.seq_number = htonl(socket->seq_number); //seq_client=X+1
		send_header.ack_number = htonl(socket->ack_number); //ack_client=0
		send_header.control = htons(FIN_ACK);
		send_header.window = htonl(socket->curr_win_size);

		//try to send the first packet(FIN_ACK)
		memset(buffer, 0, MICROTCP_RECVBUF_LEN);
		memcpy(buffer, &send_header, sizeof(microtcp_header_t));
		send_header.checksum = htonl(crc32(buffer, sizeof(buffer)));

		//printf("Before first send of shutdown in client (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));

		if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, addr, len) < 0)
		{
			perror("Error in microtcp_shutdown unable to send the first packet(FIN_ACK).");
			return -1;
		}
		//we sent the first packet and we wait for response
		//try to receive the second packet(ACK)
		if (recvfrom(socket->sd, recv_header, sizeof(microtcp_header_t), 0, addr, &len) == -1)
		{
			perror("Error in microtcp_shutdown unable to receive the second packet(ACK).");
			return -1;
		}
		//		printf("after first receive in client (seq,ack) :%d,%d\n", ntohl(recv_header->seq_number), ntohl(recv_header->ack_number));
		tmpcheck = ntohl(recv_header->checksum);
		recv_header->checksum = 0;
		memset(buffer, 0, MICROTCP_RECVBUF_LEN);
		memcpy(buffer, recv_header, sizeof(microtcp_header_t));
		if (crc32(buffer, sizeof(buffer)) != tmpcheck)
		{ //error on checksum
			perror("Error in  microtcp_shutdown in checksum at the second packet(ACK).");
			return -1;
		}
		//we received the second packet
		//is it an ACK?
		if (ntohs(recv_header->control) != ACK)
		{
			perror("Error in microtcp_shutdown the second packet is not ACK.");
			return -1;
		}
		//printf("before error(ack,seq):%d,%d\n", ntohl(recv_header->ack_number), ntohl(send_header.seq_number)+1);
		if (ntohl(recv_header->ack_number) != ntohl(send_header.seq_number) + 1)
		{
			perror("Error in microtcp_shutdown at the second packet(ACK) we do not have ack numbers.");
			return -1;
		}

		//it is ACK so ...we close
		socket->state = CLOSING_BY_HOST;
		//try to receive the third packet(FIN_ACK)
		if (recvfrom(socket->sd, recv_header, sizeof(microtcp_header_t), 0, addr, &len) == -1)
		{
			perror("Error in microtcp_shutdown unable to receive the third packet(FIN_ACK).");
			return -1;
		}
		//		printf("after second receive in client (seq,ack) :%d,%d\n", ntohl(recv_header->seq_number), ntohl(recv_header->ack_number));
		tmpcheck = ntohl(recv_header->checksum);
		recv_header->checksum = 0;
		memset(buffer, 0, MICROTCP_RECVBUF_LEN);
		memcpy(buffer, recv_header, sizeof(microtcp_header_t));
		if (crc32(buffer, sizeof(buffer)) != tmpcheck)
		{ //error on checksum
			perror("Error in  microtcp_shutdown in checksum at the fourth packet(FIN_ACK).");
			return -1;
		}
		//we received the third packet
		//is it a FIN_ACK?
		if (ntohs(recv_header->control) != FIN_ACK)
		{
			perror("Error in microtcp_shutdown the third packet is not FIN_ACK.");
			return -1;
		}

		send_header.seq_number = htonl(recv_header->ack_number);	 //seq=ack_server=X+1
		send_header.ack_number = htonl(recv_header->seq_number + 1); //ack=seq_server+1=Y+1
		send_header.control = htons(ACK);
		send_header.window = htonl(socket->curr_win_size);
		send_header.checksum = 0;
		memset(buffer, 0, MICROTCP_RECVBUF_LEN);
		memcpy(buffer, &send_header, sizeof(microtcp_header_t));
		send_header.checksum = htonl(crc32(buffer, sizeof(buffer)));

		//printf("Before second send of shutdown in client (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));
		//try to send the fourth packet(ACK)
		if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, addr, len) < 0)
		{
			perror("Error in microtcp_shutdown unable to send the fourth packet(ACK).");
			return -1;
		}
		//we sent the fourth packet
	}
	socket->state = CLOSED;
	return 0;
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,
			  int flags)
{
	/* Your code here */
	microtcp_header_t *recv_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));
	microtcp_header_t send_header;
	int i = 0, chunks, its_timeout = 0;
	int slow_start = 0;
	int cong_avoidance = 0, triple_dup_ack = 0, do_retransmit = 0;
	int lost_packet;
	uint32_t tmpcheck;
	char *buf2 = (char *)malloc(sizeof(char) * length);
	uint8_t buf_for_check[sizeof(microtcp_header_t)];
	socket->recvbuf = (char *)malloc(sizeof(char) * MICROTCP_RECVBUF_LEN);
	char *packet = (char *)malloc(sizeof(char) * ((sizeof(microtcp_header_t) + MICROTCP_MSS)));
	//char*  buf_for_check = (char*)malloc(sizeof(char)*sizeof(microtcp_header_t));//just for ACKs
	char *check_buf = (char *)malloc(sizeof(char) * ((sizeof(microtcp_header_t) + MICROTCP_MSS))); //for all packet
	uint32_t prev_ack = socket->ack_number, curr_ack = socket->ack_number;
	struct sockaddr *addr;
	socklen_t len = sizeof(socket->address);
	addr = (struct sockaddr *)&socket->address;
	uint16_t FIN = fin_fix(1, 0), ACK = ack_fix(1, 0), FIN_ACK = ack_fix(1, FIN);
	ssize_t sent_bytes, bytes_to_send, remaining, data_sent = 0;
	struct timeval timeout;
	memcpy(buf2, buffer, length);
	timeout.tv_sec = 0;
	timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
	if (!recv_header) //check malloc
	{
		perror("Error in microtcp_send in malloc of recv_header.");
		return -1;
	}
	if (!packet) //check malloc
	{
		perror("Error in microtcp_send in malloc of packet.");
		return -1;
	}
	if (!check_buf) //check malloc
	{
		perror("Error in microtcp_send in malloc of check_buf.");
		return -1;
	}
	if (!socket->recvbuf) //check malloc
	{
		perror("Error in microtcp_send in malloc of  socket->recvbuf.");
		return -1;
	}
	remaining = length;
	while (data_sent < length)
	{
		//printf("current win size,cwnd,remaining:%d,%d,%d\n", socket->curr_win_size, socket->cwnd, remaining);
		bytes_to_send = min(socket->curr_win_size, socket->cwnd, remaining);
		//printf("bytes to sent:%d\n", bytes_to_send);
		chunks = bytes_to_send / MICROTCP_MSS;
		for (i = 0; i < chunks; i++)
		{
			memset(&send_header, 0, sizeof(microtcp_header_t));
			send_header.seq_number = htonl(socket->seq_number);
			send_header.ack_number = htonl(socket->ack_number);
			send_header.data_len = htonl(MICROTCP_MSS);
			memcpy(check_buf, &send_header, sizeof(microtcp_header_t));

			memcpy(check_buf + sizeof(microtcp_header_t), buffer, MICROTCP_MSS);

			send_header.checksum = htonl(crc32(check_buf, sizeof(check_buf)));

			memcpy(packet, &send_header, sizeof(microtcp_header_t));
			memcpy(packet + sizeof(microtcp_header_t), buffer, MICROTCP_MSS);
			//printf("Before send in microtcp_send (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));

			sent_bytes = sendto(socket->sd, packet, sizeof(microtcp_header_t) + MICROTCP_MSS, 0, addr, len);
			if (sent_bytes < 0)
			{
				perror("Error in microtcp_send\n");
				return -1;
			}
			socket->seq_number = ntohl(send_header.seq_number) + (sent_bytes - sizeof(microtcp_header_t));
			socket->ack_number = ntohl(send_header.ack_number) + 1;
			buffer = buffer + MICROTCP_MSS;
		}
		/* Check if there is a semi -filled chunk */
		if (bytes_to_send % MICROTCP_MSS != 0)
		{
			chunks++;
			packet = (char *)malloc(sizeof(char) * ((sizeof(microtcp_header_t) + bytes_to_send)));
			memset(&send_header, 0, sizeof(microtcp_header_t));
			send_header.seq_number = htonl(socket->seq_number);
			send_header.ack_number = htonl(socket->ack_number);
			send_header.data_len = htonl(bytes_to_send % MICROTCP_MSS);
			memcpy(check_buf, &send_header, sizeof(microtcp_header_t));
			memcpy(check_buf + sizeof(microtcp_header_t), buffer, bytes_to_send % MICROTCP_MSS);
			send_header.checksum = htonl(crc32(check_buf, sizeof(check_buf)));
			memcpy(packet, &send_header, sizeof(microtcp_header_t));
			memcpy(packet + sizeof(microtcp_header_t), buffer, bytes_to_send % MICROTCP_MSS);
			//printf("Before send in microtcp_send (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));
			sent_bytes = sendto(socket->sd, packet, sizeof(microtcp_header_t) + bytes_to_send % MICROTCP_MSS, 0, addr, len);
			if (sent_bytes < 0)
			{
				perror("Error in microtcp_send\n");
				return -1;
			}
			socket->seq_number = ntohl(send_header.seq_number) + (sent_bytes - sizeof(microtcp_header_t));
			socket->ack_number = ntohl(send_header.ack_number) + 1;
			buffer = buffer + bytes_to_send % MICROTCP_MSS;
		}

		/* Get the ACKs */
		for (i = 0; i < chunks; i++)
		{
			if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
			{
				perror("setsockopt");
			}
			if (recvfrom(socket->sd, recv_header, sizeof(microtcp_header_t), 0, addr, &len) == -1)
			{
				its_timeout = 1;
			}
			tmpcheck = ntohl(recv_header->checksum);
			recv_header->checksum = 0;
			memset(buf_for_check, 0, sizeof(microtcp_header_t));
			memcpy(buf_for_check, recv_header, sizeof(microtcp_header_t));
			//printf("%d,%d\n", crc32(buf_for_check, sizeof(buf_for_check)), tmpcheck);
			if (crc32(buf_for_check, sizeof(buf_for_check)) != tmpcheck)
			{ //error on checksum
				perror("Error in  microtcp_send in checksum when receive ACKs.");
				return -1;
			}

			if (its_timeout)
			{
				printf("TIMEOUT\n");
				socket->ssthresh = socket->cwnd / 2;
				socket->cwnd = min2(MICROTCP_MSS, socket->ssthresh);
				break;
			}
			//printf("After receive in microtcp_send (seq,ack) :%d,%d\n", (recv_header->seq_number), (recv_header->ack_number));

			//printf("data length:%d\n", recv_header->data_len);

			//socket->curr_win_size = ntohs(recv_header->window);
			//printf("curr win size:%d\n", socket->curr_win_size);
			if (i == 0)
			{
				prev_ack = ntohl(recv_header->ack_number);
			}
			else
			{

				prev_ack = curr_ack;
			}
			curr_ack = ntohl(recv_header->ack_number);
			//printf("prev ack,current ack:%d,%d\n", prev_ack, curr_ack);
			if (prev_ack == curr_ack)
			{
				//printf("DUPLICATE ACK\n");
				triple_dup_ack++;
			}
			else
			{
				triple_dup_ack = 0;
			}
			//printf(" duplicate ack:%d\n", triple_dup_ack);
			if (triple_dup_ack == 3)
			{ //3 duplicate ACK
				//printf("3 DUPLICATE ACK\n");
				do_retransmit = 1;
				//printf("i:%d\n", i);
				lost_packet = (i - 3) + 1; //which was the lost packet
										   //	triple_dup_ack = 0;

				socket->ssthresh = socket->cwnd / 2;
				socket->cwnd = socket->cwnd / 2 + 1;
				break;
			}
		}
		/* Retransmissions */
		if (do_retransmit || its_timeout)
		{
			//printf("RETRANSMISSION\n");
			memset(&send_header, 0, sizeof(microtcp_header_t));
			socket->seq_number = ntohl(recv_header->ack_number);
			socket->ack_number = ntohl(recv_header->seq_number);
			//remaining -= lost_packet* MICROTCP_MSS;
			remaining -= ntohl(recv_header->ack_number) - init_seq;

			data_sent += lost_packet * MICROTCP_MSS;
			printf("%d\n", lost_packet * MICROTCP_MSS);
			//buffer = buf2 + ntohl(recv_header->ack_number) - init_seq;
			//memcpy(buffer , buf2 + ntohl(recv_header->ack_number) - init_seq, length- ntohl(recv_header->ack_number) - init_seq );

			//printf("REMAINING : %d\n", remaining);
			//printf("RETRANSMIT FROM PACKET WITH SEQ :  %d\n", ntohl(recv_header->ack_number) - init_seq);

			buffer -= remaining;
			//printf("seq,ack,remaining,data:%d,%d,%d,%d\n", socket->seq_number, socket->ack_number, remaining, data_sent);
			triple_dup_ack = 0;
			do_retransmit = 0;
			lost_packet = 0;
			continue;
		}
		triple_dup_ack = 0;
		/* Update window */
		//socket->curr_win_size = socket->curr_win_size - data_sent;
		/* Update congestion control */
		if (socket->cwnd <= socket->ssthresh)
		{ //slow start
			socket->cwnd = socket->cwnd * 2;
		}
		else
		{ //congestion avoidance
			socket->cwnd = socket->cwnd + MICROTCP_MSS;
		}

		remaining -= bytes_to_send;
		data_sent += bytes_to_send;
	}

	return data_sent;
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
	/* Your code here */
	microtcp_header_t *recv_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));
	microtcp_header_t send_header;
	int i = 0, x;
	static int receives;
	uint32_t tmpcheck;
	uint32_t recv_seq, recv_ack;
	socket->recvbuf = (char *)malloc(sizeof(char) * MICROTCP_RECVBUF_LEN);
	char *check_buf = (char *)malloc(sizeof(char) * (MICROTCP_MSS + sizeof(microtcp_header_t)));
	int recv = 0;
	uint8_t buf_for_check[sizeof(microtcp_header_t)];
	struct sockaddr *addr;
	socklen_t len = sizeof(socket->address);
	addr = (struct sockaddr *)&socket->address;
	ssize_t received_bytes, data;
	uint32_t prev_ack = socket->ack_number, prev_seq = socket->seq_number;
	ssize_t prev_data = 0;
	uint16_t FIN = fin_fix(1, 0), ACK = ack_fix(1, 0), FIN_ACK = ack_fix(1, FIN);
	if (!recv_header) //check malloc
	{
		perror("Error in microtcp_recv in malloc of recv_header.");
		return -1;
	}
	if (!check_buf) //check malloc
	{
		perror("Error in microtcp_recv in malloc of check_buf.");
		return -1;
	}
	if (!socket->recvbuf) //check mallocf
	{
		perror("Error in microtcp_recv in malloc of socket->recvbuf.");
		return -1;
	}

	received_bytes = recvfrom(socket->sd, socket->recvbuf, (MICROTCP_MSS + sizeof(microtcp_header_t)), 0, addr, &len);
	if (received_bytes < 0)
	{
		perror("Error in microtcp_recv\n");
		return -1;
	}
	receives++;
	socket->buf_fill_level = socket->buf_fill_level + received_bytes;
	//printf("received bytes+header:%d\n", received_bytes);
	//printf("received data:%d\n", received_bytes- sizeof(microtcp_header_t));
	memcpy(recv_header, socket->recvbuf, sizeof(microtcp_header_t));
	recv_seq = ntohl(recv_header->seq_number);
	recv_ack = ntohl(recv_header->ack_number);

	//printf("After receive in microtcp_recv (seq,ack) :%d,%d\n", (recv_seq), (recv_ack));
	if (ntohs(recv_header->control) == (FIN_ACK))
	{
		socket->seq_number = recv_ack;
		socket->ack_number = recv_seq + 1;
		socket->state = CLOSING_BY_PEER;
		return -1;
	}
	//printf("received bytes:%d\n", received_bytes);

	tmpcheck = ntohl(recv_header->checksum);

	recv_header->checksum = 0;

	memset(check_buf, 0, (MICROTCP_MSS + sizeof(microtcp_header_t)));

	memcpy(check_buf, recv_header, sizeof(microtcp_header_t));

	memcpy(check_buf + sizeof(microtcp_header_t), socket->recvbuf + sizeof(microtcp_header_t), received_bytes - sizeof(microtcp_header_t));

	//printf("recv seq,socket->ack_number:%d,%d\n", recv_seq, socket->ack_number);

	/*time_t now;
	struct tm *tm;
	now = time(0);
	if ((tm = localtime(&now)) == NULL) {
		printf("Error extracting time stuff\n");
		return 1;
	}
	   srand(tm->tm_sec);*/
	srand(time(NULL));
	x = (rand() % 5);
	//printf("random number:%d\n", x);
	//printf("recv seq,socket->ack:%d,%d\n", recv_seq, socket->ack_number);
	if (((crc32(check_buf, sizeof(check_buf))) != tmpcheck) || (recv_seq != (socket->ack_number) && receives != 1) /*|| (x <= 3)*/)
	{ //error on checksum or wrong seq number
		//printf("SEND PREV ACK.\n");
		memset(&send_header, 0, sizeof(microtcp_header_t));

		send_header.seq_number = htonl(socket->seq_number);
		send_header.ack_number = htonl(socket->ack_number);

		//received_bytes = 0;
		//return -1;
	}
	else
	{
		memset(&send_header, 0, sizeof(microtcp_header_t));
		recv = 1;
		send_header.seq_number = htonl(recv_ack);												  
		send_header.ack_number = htonl((recv_seq) + (received_bytes - sizeof(microtcp_header_t))); 
		socket->curr_win_size = socket->curr_win_size - (received_bytes - sizeof(microtcp_header_t));
		socket->seq_number = ntohl(send_header.seq_number);
		socket->ack_number = ntohl(send_header.ack_number);
		send_header.window = htons(socket->curr_win_size);
		//memcpy(buffer, (socket->recvbuf)+ sizeof(microtcp_header_t), received_bytes- sizeof(microtcp_header_t));

		memcpy(buffer, check_buf + sizeof(microtcp_header_t), received_bytes - sizeof(microtcp_header_t));

		free(socket->recvbuf);
		socket->buf_fill_level = socket->buf_fill_level - received_bytes;
		socket->curr_win_size = socket->curr_win_size + (received_bytes - sizeof(microtcp_header_t));
	}
	send_header.control = htons(ACK);
	//send_header.data_len = recv_header->data_len;
	//printf("curr win size:%d\n", socket->curr_win_size);

	//printf("send head win:%d\n", ntohs(send_header.window));
	memset(buf_for_check, 0, sizeof(microtcp_header_t));
	memcpy(buf_for_check, &send_header, sizeof(microtcp_header_t));
	send_header.checksum = htonl(crc32(buf_for_check, sizeof(buf_for_check)));

	//printf("Before send in microtcp_recv (seq,ack) :%d,%d\n", (send_header.seq_number), (send_header.ack_number));
	//sent_3_dup_ack(socket, socket->seq_number, socket->ack_number);
	if (sendto(socket->sd, (void *)&send_header, sizeof(microtcp_header_t), 0, addr, len) < 0)
	{
		perror("Error when send ACK.");
		return -1;
	}

	//printf("================================================================\n");
	if (received_bytes != 0)
		return received_bytes - sizeof(microtcp_header_t);
}

uint16_t ack_fix(int set_, uint16_t control)
{
	uint16_t i0, i1;
	i0 = 65527; //1111111111110111
	i1 = 8;		//0000000000001000
	if (set_ == 0)
		control = i0 & control;
	if (set_ == 1)
		control = i1 | control;
	return control;
}
uint16_t syn_fix(int set_, uint16_t control)
{
	uint16_t i0, i1;
	i0 = 65533; //1111111111111101
	i1 = 2;		//0000000000000010
	if (set_ == 0)
		control = i0 & control;
	if (set_ == 1)
		control = i1 | control;
	return control;
}
uint16_t fin_fix(int set_, uint16_t control)
{
	uint16_t i0, i1;
	i0 = 65534; //1111111111111110
	i1 = 1;		//0000000000000001
	if (set_ == 0)
		control = i0 & control;
	if (set_ == 1)
		control = i1 | control;
	return control;
}
ssize_t min(ssize_t n1, ssize_t n2, ssize_t n3)
{
	if (n1 < n2 && n1 < n3)
		return n1;
	if (n2 < n1 && n2 < n3)
		return n2;
	if (n3 < n2 && n3 < n1)
		return n3;
	return n1;
}
ssize_t min2(ssize_t n1, ssize_t n2)
{
	if (n1 < n2)
		return n1;
	if (n2 < n1)
		return n2;
	return n1;
}
