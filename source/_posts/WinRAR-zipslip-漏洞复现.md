---
title: WinRAR zipslip 漏洞复现
date: 2023-05-24 01:56:46
tags:
---

### 【漏洞详情】

这是一个存在于WinRAR上的漏洞，用它来可以获得受害者计算机的控制。攻击者只需利用此漏洞构造恶意的压缩文件，当受害者使用WinRAR解压该恶意文件时便会触发漏洞。该漏洞是由于WinRAR所使用的一个陈旧的动态链接库UNACEV2.dll所造成的，没有任何的基础保护机制(ASLR,DEP等)。动态链接库的作用是处理ACE格式文件。而WinRAR解压ACE文件时，由于没有对文件名进行充分过滤，导致其可实现目录穿越，将恶意文件写入任意目录,甚至可以写入文件至开机启动项，导致代码执行。

### 【验证工具】

    WinACE

    WinRAR 5.6

    Hex Editor Neo

    Acefile.py

### 【影响版本】

    影响版本：

    WinRAR < 5.70 Beta 1

    Bandizip < = 6.2.0.0

    好压(2345压缩) < = 5.9.8.10907

    360压缩 < = 4.0.0.1170

### 【验证详情】

*   验证条件

*   验证过程

    *   首先在桌面上创建一个普通的txt文件。

        ![](/img/winrar/1.png)

    *   下载安装WinACE进行压缩,这里选中store full path以保存完整路径。

        ![](/img/winrar/2.png)

    *   使用acefile脚本查看ace文件的header信息，脚本地址为

        ```
        https://github.com/droe/acefile/blob/master/acefile.py
        ```

    * 执行命令

        ```
        python3 poc.py --headers /Volumes/\[C\]\ Windows\ 7/Users/lllh/Desktop/test.ace
        ```

        ![](/img/winrar/3.png)

    *   使用16进制编辑器打开该ace文件。下面结合acefile.py给出的header信息理解ace文件各部分内容的含义。  
        下面第一个圈对应的是hdr_crc也就是一个校验和，值为0x85e1；第二个圈是hdr_size，也就是从hdr_size到文件内容前这一段的长度，值为0x003a；第三个圈是filename的长度，值为0x001b；第四部分是filename。

        ![](/img/winrar/4.png)

    *   该漏洞的利用思路是通过修改文件名，形成目录穿越漏洞，将恶意文件写入任意目录，因此这里目标是修改filename段。修改完filename，需要再依次向前修改文件头，使得文件可用。

    *   首先把filename修改为c:\\c:\\test.txt。该filename长度为14，即16进制的0x0e，因此修改文件中的filename长度字段为`0e 00`。

        ![](/img/winrar/5.png)

    *   然后修改hdr_size，为下图中选中部分，长度是45，即16进制的0x2d。修改下图圈中字段为`2d 00`。

        ![](/img/winrar/6.png)

    *   下一步修改hdr_crc。首先通过之前的脚本，查看该文件现在正确的hdr_crc值。直接执行该脚本，会报错。

        ![](/img/winrar/7.png)

    *   在源代码里定位`header CRC failed`。

        ![](/img/winrar/8.png)

    *   这里ace_crc16(buf)的值就是ace文件hdr_cr对应的值，直接打印出该值并将该位置的值修改即可。

        ![](/img/winrar/9.png)

    *   对应的值为2227，即16进制的0x08b3。修改文件中对应的值为`b3 08`。

        ![](/img/winrar/10.png)

    *   最终的文件内容为

        ![](/img/winrar/11.png)

    *   再次执行脚本，可以正常解析，并看到filename已经修改成功。

        ![](/img/winrar/12.png)

    *   由于我将文件穿越路径设为C盘根目录，这个目录需要管理员权限才能写入，因此需要以管理员身份打开WinRAR，然后解压缩此ace文件到任意目录，可以在C盘根目录下看到生成了test.txt。漏洞复现完成。

        ![](/img/winrar/13.png)

### 【漏洞修复】

- WinRAR升级到5.70 Beta 1

- 删除UNACEV2.dll文件