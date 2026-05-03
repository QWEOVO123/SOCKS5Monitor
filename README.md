# 一个运行在Windows上的SOCKS5代理/探测程序

**支持探测HTTP/TLS SNI**
**对于Shadowsocks流量探测目前误报率很高**
**支持异步(async)探测和同步阻塞探测**
启动参数加

```
--async
```

即可开启异步
加入`--async=[int1-8]`比如`--async=4`即可开启4workers异步探测
