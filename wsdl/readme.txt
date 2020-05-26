
说明：

1. 这些文件根据ONVIF WSDL and XML Schemas Specifications_download_2013.09.16目录中的文件修改了路径，由指定网址改为当前路径，用于本地生成。


2. 生成onvif.h头文件命令：

wsdl2h -o onvif.h -c -s -t ./typemap.dat devicemgmt.wsdl media.wsdl event.wsdl display.wsdl deviceio.wsdl imaging.wsdl ptz.wsdl receiver.wsdl recording.wsdl search.wsdl remotediscovery.wsdl replay.wsdl analytics.wsdl analyticsdevice.wsdl actionengine.wsdl accesscontrol.wsdl doorcontrol.wsdl advancedsecurity.wsdl

请分行复制，并且保证各文件名之间的空格符。目前一共有18个wsdl文件。为了保证全功能，最好一次性生成包含所有功能的源码。


3. 生成源文件：
soapcpp2 -c onvif.h -x -I /home/samba/ONVIF_TEST_2013.09.16/gsoap_2.8.16/gsoap-2.8/gsoap/import/ -I /home/samba/ONVIF_TEST_2013.09.16/gsoap_2.8.16/gsoap-2.8/gsoap/

请分行复制，并且保证各文件名之间的空格符。注意确定以上两个路径，必要的话需要修改路径。

生成过程中有错误：

wsa5.h(288): **ERROR**: remote method name clash: struct/class 'SOAP_ENV__Fault' already declared at line 274


打开gsoap_2.8.16\gsoap-2.8\gsoap\import\wsa5.h   文件，  修改277行，SOAP_ENV__Fault， 直接去掉或者重命名为SOAP_ENV__Fault_alex。


继续执行命令，看到Compilation successful 表示生成源文件成功。


guog
2013.09.16 