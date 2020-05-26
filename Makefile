SOAP_PATH = ./soap
CC = gcc -g
INCLUDE = -I $(SOAP_PATH)

SERVER_OBJS = soap/soapC.o soap/stdsoap2.o soap/soapServer.o soap/duration.o src/onvif_interface.o src/onvif_server.o  src/onvif_function.o

FIND_OBJS = soap/soapC.o soap/stdsoap2.o soap/soapServer.o soap/duration.o src/onvif_interface.o src/onvif_find.o  src/onvif_function.o

all: find server

server: $(SERVER_OBJS) 
	$(CC) $(INCLUDE) -o onvif_server $(SERVER_OBJS) 

find: $(FIND_OBJS) 
	$(CC) $(INCLUDE) -o onvif_find $(FIND_OBJS) 

clean:
	rm -f soap/*.o src/*.o onvif_server onvif_find
