# WeChatDBKey

⚠️ 本项目仅供学习交流使用，请勿用于非法用途，否则后果自负。

## 介绍

此项目可以无视Windows微信的版本可以直接获取微信数据库的密钥
使用[WeChatDBDec](https://github.com/git-jiadong/WeChatDBDec)可以将数据库解密

## 使用方法

在电脑登陆需要获取数据库密钥的微信
```shell
git clone https://github.com/git-jiadong/WeChatDBKey.git
cd WeChatDBKey
go build .
./WeChatDBKey.exe
```

## Q&A

- 如果出现获取DB Key失败的情况，请带上版本给作者提[issues](https://github.com/git-jiadong/WeChatDBKey/issues)
- 相同的微信号在不同电脑上面的密钥是不同的
