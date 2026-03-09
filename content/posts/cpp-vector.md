+++
date = '2026-03-09T07:54:32+08:00'
title = 'C++ Vector'
showToc = true
tags = ['C++', 'STL']

+++

## 创建 vector

```cpp
#include <vector>

vector<int> v0;

// 创建一个初始空间为 3 的 vector，元素默认值为 0
vector<int> v1(3);

// 创建一个初始空间为 3 的 vector，元素默认值是 2
vector<int> v2(3, 2);

// 创建一个 v2 的拷贝 v3，元素内容和 v2 一样
vector<int> v3(v2);

// 创建一个 v3 的拷贝到 v4，内容是 { v3[1], v3[2] }，包前不包后;
vector<int> v4(v3.begin() + 1, v3.begin() + 3);
```

## 元素访问

- `vector.at(pos)` 返回 `vector` 中下标为 `pos` 的引用
- `vector[pos]` 返回 `vector` 中下标为 `pos` 的引用，不执行越界检查
- `vector.front()` 返回首元素的引用（`vector.begin()` 是迭代器，和这个不同）
- `vector.back()` 返回末元素的引用 （`vector.end()` 是迭代器，没有元素，和这个不同）
- `vector.data()` 返回首元素的指针（`vector` 的空间是连续的）

## 迭代器

- `vector.begin()` 返回首元素的迭代器，`*begin = front`
- `vector.end()` 返回末元素的迭代器，没有元素
- `vector.rbegin()` 返回指向逆向数组的首元素的迭代器，可以理解为正向容器的末元素
- `vector.rend()` 返回指向逆向数组末元素后一位置的迭代器，对应容器首的前一个位置，没有元素
- 上述迭代器名前加上一个 `c` 为只读迭代器

## 长度和容量

**注意，`vector` 的长度（size）指有效元素数量，而容量（capacity）指分配的内存长度**

### 长度

- `vector.empty()` 返回一个 `bool` 值，即 `vector.begin() == vector.end()`
- `vector.size()` 返回容器长度，即 `distance(vector.begin(), vector.end())`
- `vector.resize(n)` 改变 `vector` 的长度为 `n`，如果 `n` 大于当前长度，则会补充元素，如果参数中提供了要补充的元素，则使用参数，否则使用默认值；如果 `n` 小于当前长度，则保留前 `n` 的元素，舍弃后面的元素
- `veector.max_size()` 返回容器的最大可能大小（一般为 `2305843009213693951`）

### 容量

- `vector.reserve()` 使得 `vector` 预留一定的内存空间，避免不必要的内存分配
- `vector.capacity()` 返回容器的容量，即已经为多少个元素分配了空间
- `vector.shrink_to_fint()` 使得 `vector` 的容量与长度一致，去除该 `vector` 没有用到的容量

## 增删改

- `vector.push_back(element)` 在末尾添加元素
- `vector.insert(iterator, ...)` 有以下几种用法：
    - `vector.insert(iterator, element)`
    - `vector.insert(iterator, element1, element2)`
    - `vector.insert(iterator, element_iterator_begin, element_iterator_end)`
    - `vector.insert(iterator, { element1, element2 })`

- `vector.clear()` 清空
- `vector.erase(iterator)` 删除元素
- `vector.pop_back()` 删除末尾元素
- `vector.swap(vector)` 交换两个 `vector` 的内容
