# -*- coding:utf-8 -*-
# @Time     : 2018/5/10 16:19
# @Author   : XXH
# @Email    : kenvinxxh@gmail.com
# @File     : md5.py
# @Software : PyCharm

#定义函数，用来产生常数T[i]，常数有可能超过32位，同样需要&0xffffffff操作。注意返回的是十进制的数
def T(i):
    result = (int(4294967296*abs(__import__("math").sin(i))))&0xffffffff
    return result

# 定义每轮中用到的函数
# RL为循环左移，注意左移之后可能会超过32位，所以要和0xffffffff做与运算，确保结果为32位
F = lambda x, y, z:((x&y)|((~x)&z))
G = lambda x, y, z:((x&z)|(y&(~z)))
H = lambda x, y, z:(x^y^z)
I = lambda x, y, z:(y^(x|(~z)))
RL = L = lambda x, n:(((x<<n)|(x>>(32-n)))&(0xffffffff))

def FF(a, b, c, d, x, s, ac):
    a = (a+F ((b), (c), (d)) + (x) + (ac)&0xffffffff)&0xffffffff;
    a = RL ((a), (s))&0xffffffff;
    a = (a+b)&0xffffffff
    return a
def GG(a, b, c, d, x, s, ac):
    a = (a+G ((b), (c), (d)) + (x) + (ac)&0xffffffff)&0xffffffff;
    a = RL ((a), (s))&0xffffffff;
    a = (a+b)&0xffffffff
    return a
def HH(a, b, c, d, x, s, ac):
    a = (a+H ((b), (c), (d)) + (x) + (ac)&0xffffffff)&0xffffffff;
    a = RL ((a), (s))&0xffffffff;
    a = (a+b)&0xffffffff
    return a
def II(a, b, c, d, x, s, ac):
    a = (a+I ((b), (c), (d)) + (x) + (ac)&0xffffffff)&0xffffffff;
    a = RL ((a), (s))&0xffffffff;
    a = (a+b)&0xffffffff
    return a

def append(append, length):
    '''
    appending
    :param append:appendstring
    :param length:length of hash
    :return:list Haven apppended
    '''
    lengthAppend = len(append) # length of appendstring
    appendFirst = [] # 第一个64位
    appendSecond =[x.encode("hex") for x in append] # 第二个64位
    appendAll = []
    # 计算每个64的padding
    appendAll.append(padding(appendFirst, length))
    appendAll.append(padding(appendSecond,lengthAppend = lengthAppend))
    return appendAll

def padding(append, length = 0, lengthAppend = 0):
    '''
    specific steps
    :param append:
    :return:string Haven apppended
    '''
    append.append('80')   # 先填充80
    while (len(append)+length+8)%64 != 0:
        append.append('00')       # append 0
    if lengthAppend != 0:
        length = 64 + lengthAppend
    append.append(reverse_hex_8bytes(length*8))  # 填充长度(小端存储)
    return "".join(i for i in append)

def reverse_hex_8bytes(length):
    '''
    little-endian limit 8 bytes(16hex,32bit)
    :param length:
    :return: little-endian of hex
    '''
    return __import__("struct").pack("<Q", length).encode("hex")

def reverse_hex_4bytes(length):
    '''
    little-endian limit 4 bytes(8hex,16bit)
    :param length:
    :return: little-endian of hex
    '''
    return __import__("struct").pack("<L", int(length, 16)).encode("hex")

def getLittleEndian(hex_str):
    '''
    little-endian of dec
    :param hex_str:
    :return:result of splited 64bytes into 4*16 message blocks with little-endian
    '''
    return [int(reverse_hex_4bytes(hex_str[i:(i+8)]), 16) for i in range(0, 128, 8)] # 截取hex_str的每4个字节(8个16进制),进行转为小端进而求出响应的10进制

def md5(hex_str, hash):
    '''
    使用ABCD(上一轮的iv)进行计算md5值
    :param A:
    :param B:
    :param C:
    :param D:
    :param hex_str: hash
    :return: split of md5
    '''
    # 对hash进行小端处理(10进制)
    A = int(reverse_hex_4bytes(hash[0:8]), 16)
    B = int(reverse_hex_4bytes(hash[8:16]), 16)
    C = int(reverse_hex_4bytes(hash[16:24]), 16)
    D = int(reverse_hex_4bytes(hash[24:32]), 16)
    a = A
    b = B
    c = C
    d = D

    # 获取hex_str的值
    M = getLittleEndian(hex_str)
    for i in range(16):
        exec "M"+str(i)+"=M["+str(i)+"]" #执行赋值语句,便于使用

    #First round
    a=FF(a,b,c,d,M0,7,0xd76aa478L)
    d=FF(d,a,b,c,M1,12,0xe8c7b756L)
    c=FF(c,d,a,b,M2,17,0x242070dbL)
    b=FF(b,c,d,a,M3,22,0xc1bdceeeL)
    a=FF(a,b,c,d,M4,7,0xf57c0fafL)
    d=FF(d,a,b,c,M5,12,0x4787c62aL)
    c=FF(c,d,a,b,M6,17,0xa8304613L)
    b=FF(b,c,d,a,M7,22,0xfd469501L)
    a=FF(a,b,c,d,M8,7,0x698098d8L)
    d=FF(d,a,b,c,M9,12,0x8b44f7afL)
    c=FF(c,d,a,b,M10,17,0xffff5bb1L)
    b=FF(b,c,d,a,M11,22,0x895cd7beL)
    a=FF(a,b,c,d,M12,7,0x6b901122L)
    d=FF(d,a,b,c,M13,12,0xfd987193L)
    c=FF(c,d,a,b,M14,17,0xa679438eL)
    b=FF(b,c,d,a,M15,22,0x49b40821L)

    #Second round
    a=GG(a,b,c,d,M1,5,0xf61e2562L)
    d=GG(d,a,b,c,M6,9,0xc040b340L)
    c=GG(c,d,a,b,M11,14,0x265e5a51L)
    b=GG(b,c,d,a,M0,20,0xe9b6c7aaL)
    a=GG(a,b,c,d,M5,5,0xd62f105dL)
    d=GG(d,a,b,c,M10,9,0x02441453L)
    c=GG(c,d,a,b,M15,14,0xd8a1e681L)
    b=GG(b,c,d,a,M4,20,0xe7d3fbc8L)
    a=GG(a,b,c,d,M9,5,0x21e1cde6L)
    d=GG(d,a,b,c,M14,9,0xc33707d6L)
    c=GG(c,d,a,b,M3,14,0xf4d50d87L)
    b=GG(b,c,d,a,M8,20,0x455a14edL)
    a=GG(a,b,c,d,M13,5,0xa9e3e905L)
    d=GG(d,a,b,c,M2,9,0xfcefa3f8L)
    c=GG(c,d,a,b,M7,14,0x676f02d9L)
    b=GG(b,c,d,a,M12,20,0x8d2a4c8aL)

    #Third round
    a=HH(a,b,c,d,M5,4,0xfffa3942L)
    d=HH(d,a,b,c,M8,11,0x8771f681L)
    c=HH(c,d,a,b,M11,16,0x6d9d6122L)
    b=HH(b,c,d,a,M14,23,0xfde5380c)
    a=HH(a,b,c,d,M1,4,0xa4beea44L)
    d=HH(d,a,b,c,M4,11,0x4bdecfa9L)
    c=HH(c,d,a,b,M7,16,0xf6bb4b60L)
    b=HH(b,c,d,a,M10,23,0xbebfbc70L)
    a=HH(a,b,c,d,M13,4,0x289b7ec6L)
    d=HH(d,a,b,c,M0,11,0xeaa127faL)
    c=HH(c,d,a,b,M3,16,0xd4ef3085L)
    b=HH(b,c,d,a,M6,23,0x04881d05L)
    a=HH(a,b,c,d,M9,4,0xd9d4d039L)
    d=HH(d,a,b,c,M12,11,0xe6db99e5L)
    c=HH(c,d,a,b,M15,16,0x1fa27cf8L)
    b=HH(b,c,d,a,M2,23,0xc4ac5665L)

    #Fourth round
    a=II(a,b,c,d,M0,6,0xf4292244L)
    d=II(d,a,b,c,M7,10,0x432aff97L)
    c=II(c,d,a,b,M14,15,0xab9423a7L)
    b=II(b,c,d,a,M5,21,0xfc93a039L)
    a=II(a,b,c,d,M12,6,0x655b59c3L)
    d=II(d,a,b,c,M3,10,0x8f0ccc92L)
    c=II(c,d,a,b,M10,15,0xffeff47dL)
    b=II(b,c,d,a,M1,21,0x85845dd1L)
    a=II(a,b,c,d,M8,6,0x6fa87e4fL)
    d=II(d,a,b,c,M15,10,0xfe2ce6e0L)
    c=II(c,d,a,b,M6,15,0xa3014314L)
    b=II(b,c,d,a,M13,21,0x4e0811a1L)
    a=II(a,b,c,d,M4,6,0xf7537e82L)
    d=II(d,a,b,c,M11,10,0xbd3af235L)
    c=II(c,d,a,b,M2,15,0x2ad7d2bbL)
    b=II(b,c,d,a,M9,21,0xeb86d391L)

    A += a
    B += b
    C += c
    D += d

    A = A&0xffffffff
    B = B&0xffffffff
    C = C&0xffffffff
    D = D&0xffffffff

    a = A
    b = B
    c = C
    d = D

    # 对每一组进行小端储存,并且拼接
    return "".join([__import__("struct").pack("<L", i).encode("hex") for i in (a, b, c, d)])
