+++
date = '2026-03-09T14:31:39+08:00'
title = 'C++ String'
showToc = true
tags = ['C++']

+++

## 创建

```cpp
#include <string> // 注意不是 <string.h>

string s;
```

## 转字符数组

- `string.data()` 不保证末尾有空字符
- `string.c_str()` 保证末尾有空字符，建议用这个

## 获取长度

- `string.size()`
- `string.length()`
- `strlen(string.c_str())`

> 注意！
> 
> 这三个函数（以及下面将要提到的 `find` 函数）的返回值类型都是 `size_t`（`unsigned long`）．因此，这些返回值不支持直接与负数比较或运算，建议在需要时进行强制转换．

## 查找

- `string.find(str, pos = 0)` 查找字符串中一个字符/字符串在含 `pos` 之后第一次出现的位置，如果没有出现，则为 `string::npos`（类型为 `size_t`/`unsigned long`，需转换）

## 截取

- `string.substr(pos, len)` 返回从 `pos` 位置开始截取最多 `len` 个字符组成的字符串

## 插入

- `string.insert(index, count, char)` 在 `index` 处连续插入 `count` 个 `char`
- `string.insert(index, str)` 在 `index` 处插入 `str`

## 擦除

- `string.erase(index, count = string.length())` 将从含 `index` 开始的 `count` 个字符删除

## 替换

- `string.replace(pos, count, str)` 将从含 `pos` 后面的 `count` 个字符替换为 `str`
- `string.replace(first: iterator, last: iterator, str)` 将以含 `first` 开始，不含 `last` 结束的字串替换为 `str`
