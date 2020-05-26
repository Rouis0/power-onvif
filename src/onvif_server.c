#include "../soap/soapStub.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/time.h>




#define ONVIF_LISTEN_PORT	80

int main(int argc, char **argv)  
{  
    printf("[%s][%d][%s][%s] onvifServer start \n", __FILE__, __LINE__, __TIME__, __func__);

    int m, s; 
	int count = 0; 
    struct soap ServerSoap;  
	int server_udp;

    soap_init(&ServerSoap);  
    soap_set_namespaces(&ServerSoap, namespaces);  

    printf("[%s][%d][%s][%s] ServerSoap.version = %d \n", __FILE__, __LINE__, __TIME__, __func__, ServerSoap.version);
	

	if(!soap_valid_socket(soap_bind(&ServerSoap, NULL, ONVIF_LISTEN_PORT, 100)))
	{
		soap_print_fault(&ServerSoap, stderr);
		exit(1);
	}


    for (;;) {  
        s = soap_accept(&ServerSoap);  

        if (s < 0) {  
            soap_print_fault(&ServerSoap, stderr); 
            exit(-1);  
        }  
        
        soap_serve(&ServerSoap);  
        soap_end(&ServerSoap);  

        printf("RECEIVE count %d, connection from IP = %lu.%lu.%lu.%lu socket = %d \r\n",
				count, ((ServerSoap.ip)>>24)&0xFF, ((ServerSoap.ip)>>16)&0xFF, ((ServerSoap.ip)>>8)&0xFF, (ServerSoap.ip)&0xFF, (ServerSoap.socket));
		count++;
    }  
    
	soap_done(&ServerSoap);

	return 0; 
} 

