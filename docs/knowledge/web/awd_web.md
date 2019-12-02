## 赛前准备

### 配路由表

https://blog.csdn.net/SJU_x1u_q1n9/article/details/81637000

```shell
route delete 0.0.0.0
route add 比赛网址ip mask 255.255.255.0 内网
route add 0.0.0.0 mask 0.0.0.0 外网
```



## 比赛开始

### ssh连接

连上之后首先备份一下网页的源码(可以准备自动化的脚本),windows下可以使用xshell,连上之后可以使用xftp进行文件的传输.

### D盾查webshell

有shell马上删了,接着要尽快的骑上去(准备骑马脚本)

### 修改ssh密码

如果是弱密码的话要改

```
passwd
```

### 数据库备份

看情况进行数据库的备份,其中database_name以及账号密码要自己在源码里面找

```sql
mysqldump -u root -p database_name > bakup.sql;
```

### 流量监控

```
上waf
find ./ -type f -name '*.php' |xargs  sed -i '1i<?php include_once "/tmp/waf.php";?>'
撤销
find ./ -type f -name '*.php' |xargs  sed -i '1d'
```

通过查看流量监控产生的日志可以看到其他队伍发送的请求,找到得分的请求并且迅速模仿.

### 文件监控

上文件监控

### 找洞写脚本

可以用postman生成python代码