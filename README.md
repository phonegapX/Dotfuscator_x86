# Dotfuscator_x86

这是一个32位windows下x86指令集的扭曲加密小工具，这个小工具是2008年做的，当时因为需要给开发的windows驱动进行一些防护，防止其他人逆向，当时能给驱动加壳的软件还不是很多，比较厉害的就是刘涛涛的扭曲加密，不过因为各种原因最后在高人的指点下自己弄了个简单的代码扭曲加密小工具用于驱动代码的保护，虽然远远谈不上完美，但是勉强也能用，呵呵。 

因为年代久远有些细节也记不清楚了，基本思路就是比如将jmp会替成 jnz xxx jz xxx, call变成push xxx,jmp target这种代码，然后可以通过多次循环变换将生成的代码进一步进行分解变换以提高代码扭曲的程度。
执行Dotfuscator.exe输出如下：

Dotfuscator 1.0
---------------
Usage:
        Dotfuscator exefile [-m{n}] [-o{outfile}]
        -m      Mutate times
        -o      Output file

比如 Dotfuscator.exe test.exe -m3 -o1.exe 将test.exe扭曲加密后输出到新的1.exe，-m3代表循环处理3次，默认是2次，如果处理次数太多，代码会急剧膨胀，并且处理时间会变的很长。

最后测试的开发环境是vs2010
