
˵����

1. ��Щ�ļ�����ONVIF WSDL and XML Schemas Specifications_download_2013.09.16Ŀ¼�е��ļ��޸���·������ָ����ַ��Ϊ��ǰ·�������ڱ������ɡ�


2. ����onvif.hͷ�ļ����

wsdl2h -o onvif.h -c -s -t ./typemap.dat devicemgmt.wsdl media.wsdl event.wsdl display.wsdl deviceio.wsdl imaging.wsdl ptz.wsdl receiver.wsdl recording.wsdl search.wsdl remotediscovery.wsdl replay.wsdl analytics.wsdl analyticsdevice.wsdl actionengine.wsdl accesscontrol.wsdl doorcontrol.wsdl advancedsecurity.wsdl

����и��ƣ����ұ�֤���ļ���֮��Ŀո����Ŀǰһ����18��wsdl�ļ���Ϊ�˱�֤ȫ���ܣ����һ�������ɰ������й��ܵ�Դ�롣


3. ����Դ�ļ���
soapcpp2 -c onvif.h -x -I /home/samba/ONVIF_TEST_2013.09.16/gsoap_2.8.16/gsoap-2.8/gsoap/import/ -I /home/samba/ONVIF_TEST_2013.09.16/gsoap_2.8.16/gsoap-2.8/gsoap/

����и��ƣ����ұ�֤���ļ���֮��Ŀո����ע��ȷ����������·������Ҫ�Ļ���Ҫ�޸�·����

���ɹ������д���

wsa5.h(288): **ERROR**: remote method name clash: struct/class 'SOAP_ENV__Fault' already declared at line 274


��gsoap_2.8.16\gsoap-2.8\gsoap\import\wsa5.h   �ļ���  �޸�277�У�SOAP_ENV__Fault�� ֱ��ȥ������������ΪSOAP_ENV__Fault_alex��


����ִ���������Compilation successful ��ʾ����Դ�ļ��ɹ���


guog
2013.09.16 