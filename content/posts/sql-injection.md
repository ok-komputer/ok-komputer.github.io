+++
date = '2025-11-12T19:32:31+08:00'
title = 'SQL 注入 - CTF Web 学习笔记'
toc = true
tocBorder = true
+++

SQL 注入就是利用应用执行 SQL 语句注入非法内容从而执行恶意查询或增删改。

## SQL 基本查询语句

从 `users` 表中查询 `id` 为 `123` 的数据：

``` sql
SELECT username, password FROM users where id = 123;
```

- `UNION` 用于合并两个或多个 SELECT 语句的结果
- `LIMIT` 用于限制返回的记录数量
- `ORDER BY` 对结果进行排序
- `--` 用于单行注释
- `/* */` 用于多行注释

``` sql
SELECT username, password FROM users1 ORDER BY id
    UNION SELECT username, password FROM users2 LIMIT 10; -- 查询
```

注意：使用 UNION 的时候要注意两个表的列数量必须相同。

## SQL 常用参数

- `user()`：当前数据库用户
- `database()`：当前数据库名
- `version()`：当前使用的数据库版本
- `@@datadir`：数据库储存数据路径
- `concat()`：联合数据，用于联合两条数据结果，如 `concat(username, 0x3a, password)`
- `group_concat()`：和 `concat()` 类似，如 `group_concat(DISTINCT+user,0x3a,password)`，用于把多条数据一次注入出来
- `concat_ws()`：用法类似
- `hex()` 和 `unhex()`：用于 hex 编码解码
- `ASCII()`：返回字符的 ASCII 码值
- `CHAR()`：把整数转换为对应的字符
- `load_file()`：以文本方式读取文件，在 Windows 中，路径设置为 \\
- `select xxoo into outfile '路径'`：权限较高时可直接写文件

## 基本注入

注释掉后面的条件以直接绕过条件。

``` sql
SELECT username, password FROM users WHERE username = 'admin' AND password = 'admin'
```

此时如果 `username` 为 `admin'--`，那么将会截断前一个引号并注释掉后面的密码验证，攻击者可以直接绕过身份验证。

## `UNION` 注入

通过 UNION 将攻击者构造的查询结果与合法查询结果合并，从而获取敏感数据。

输入：

``` sql
' UNION SELECT null, username, password FROM users --
```

将 `users` 表的 `username` 和 `password` 数据作为结果返回。

## 错误型注入

通过故意触发数据库错误，利用错误信息推测表名、列名或数据。

输入：

``` sql
' AND 1=CONVERT(int, (SELECT @@version)) --
```

可以通过报错获得数据库版本信息。