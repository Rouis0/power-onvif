# 实时推流系统

## 功能简介
本项目中实现了ONVIF的设备的发现服务和主要的逻辑服务，包括设备信息、流媒体信息的获取操作，结合v4l2Server等RTSP服务器+OneNET物联网开发平台SDK可实现一个实时的推流系统，可在远程获取画面并对设备进行控制

## 文件结构
- soap：通过onvif框架生成工具自动生成的文件，在开发中需要引用到
- src：逻辑实现文件
    - onvif_find.c：发现服务启动文件（只做监听操作）
    - server_find.c：功能服务启动文件（只做监听操作）
    - onvif_interface.c：对onvif协议接口的实现文件
    - onvif_function.c：通用接口文件
- tools：存放一些脚本工具
- wsdl：开发onvif用到的wsdl文档
- xml：生成onvif框架时产生的xml文档文件

## 使用步骤
### STEP 1 
运行make对项目进行编译，在根目录将会产生onvif_find和onvif_server执行文件
1. onvif_find设备发现服务，用于监听UDP
2. onvif_server设备主要功能服务，用于处理各种逻辑操作

### STEP 2
安装RTSP服务器，以[v4l2Server](https://github.com/JdeRobot4Air/v4l2server)为例：


运行tools目录下的v4l2rtspserver.sh文件安装v4l2server流媒体服务器，安装完毕后通过命令启动RTSP服务器，并根据运行参数修改src/onvif_interface.c的RTSP_SERVER配置常量
```
v4l2rtspserver -P 8554 -u 'h264' -W 1280 -H 720 /dev/video0
```

### STEP 3
分别运行两个执行文件，此时可以在局域网内对ONVIF服务对设备进行测试和查看设备
```
./onvif_find
./onvif_server
```


### STEP 4
在物联网开发平台注册账号，并对接开发平台，实现远程控制。

以OneNET为例子：
- 首先在OneNET开发平台注册账号，然后创建视频产品
- 编译OneNET开发平台的视频SDK，详细见[官方文档](https://open.iot.10086.cn/doc/art566.html#108)
- 根据注册的产品修改SDK的配置文件
- 运行程序，即可在OneNET平台看到视频画面和操作界面


