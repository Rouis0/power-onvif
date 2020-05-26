#include "../soap/soapStub.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/time.h>



#define ONVIF_LISTEN_PORT	3702


int main(int argc,char ** argv)
{
	printf("[%s][%d][%s][%s] findServer start \n", __FILE__, __LINE__, __TIME__, __func__);

	int count = 0;
	struct soap ServerSoap;
	struct ip_mreq mcast;
	
	soap_init1(&ServerSoap, SOAP_IO_UDP | SOAP_XML_IGNORENS);
	soap_set_namespaces(&ServerSoap,  namespaces);
	
	printf("[%s][%d][%s][%s] ServerSoap.version = %d \n", __FILE__, __LINE__, __TIME__, __func__, ServerSoap.version);
	
	if(!soap_valid_socket(soap_bind(&ServerSoap, NULL, ONVIF_LISTEN_PORT, 100)))
	{
		soap_print_fault(&ServerSoap, stderr);
		exit(1);
	}
	
	mcast.imr_multiaddr.s_addr = inet_addr("239.255.255.250");
	mcast.imr_interface.s_addr = htonl(INADDR_ANY);

	if(setsockopt(ServerSoap.master, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mcast, sizeof(mcast)) < 0)
	{
		printf("setsockopt error! error code = %d,err string = %s\n",errno,strerror(errno));
		return 0;
	}

	for(;;)
	{
		if(soap_serve(&ServerSoap))
		{
			soap_print_fault(&ServerSoap, stderr);
		}

		soap_destroy(&ServerSoap);
		soap_end(&ServerSoap);

		printf("RECEIVE count %d, connection from IP = %lu.%lu.%lu.%lu socket = %d \r\n",
				count, ((ServerSoap.ip)>>24)&0xFF, ((ServerSoap.ip)>>16)&0xFF, ((ServerSoap.ip)>>8)&0xFF, (ServerSoap.ip)&0xFF, (ServerSoap.socket));
		count++;
	}

	soap_done(&ServerSoap);

	return 0;
}