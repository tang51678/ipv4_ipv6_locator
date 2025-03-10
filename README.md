以下是整理好的 `README.md` 文件内容，复制后不会乱码，可以直接保存为 `README.md` 文件：

---

# IP 归属地查询工具

## 概述
这是一个用于查询 IP 地址归属地的 Python 脚本，支持 IPv4 和 IPv6 地址的查询。它基于以下两个数据库文件：
1. **`qqwry.dat`**：用于查询 IPv4 地址的归属地。
2. **`ipv6wry.db`**：用于查询 IPv6 地址的归属地。

脚本通过读取这些数据库文件，解析 IP 地址的归属地信息，并返回国家、地区等详细信息。

---

## 功能特性
- **支持 IPv4 和 IPv6**：同时支持 IPv4 和 IPv6 地址的查询。
- **高效查询**：使用二分查找算法，查询速度快。
- **灵活配置**：允许用户自定义数据库文件的路径。
- **异常处理**：对 IP 地址格式错误、文件读取失败等情况进行处理。
- **资源管理**：自动关闭文件句柄，避免资源泄漏。
- **中文支持**：返回的归属地信息支持中文显示。

---

## 运行原理

### 1. 数据库文件解析
- **`qqwry.dat`**：存储 IPv4 地址段及其对应的归属地信息。
- **`ipv6wry.db`**：存储 IPv6 地址段及其对应的归属地信息。

脚本通过读取这些二进制文件，解析其中的索引和数据，找到目标 IP 地址的归属地信息。

### 2. IP 地址处理
- 对于 IPv4 地址，脚本将其转换为 32 位无符号整数，并通过二分查找在数据库中定位对应的记录。
- 对于 IPv6 地址，脚本将其转换为 128 位二进制数据，并通过二分查找在数据库中定位对应的记录。

### 3. 二分查找算法
- 使用二分查找算法在数据库中快速定位目标 IP 地址的归属地信息。
- 通过比较 IP 地址的大小，逐步缩小搜索范围，直到找到匹配的记录。

### 4. 数据解析
- 从数据库中读取记录，解析出国家、地区等信息。
- 对于重定向记录，脚本会跳转到指定位置继续读取数据。

### 5. 结果返回
- 脚本将查询结果以字典形式返回，包含以下字段：
  - `ip`：查询的 IP 地址。
  - `country`：国家信息。
  - `area`：地区信息。

---

## 使用方法

### 1. 安装依赖
确保已安装 Python 3.x，无需额外依赖。

### 2. 下载数据库文件
将以下文件放置于 `./db` 目录下：
- `qqwry.dat`：IPv4 数据库文件。
- `ipv6wry.db`：IPv6 数据库文件。

### 3. 运行脚本
```bash
python ip_location_query.py
```

### 4. 示例代码
```python
from ip_location_query import IpLocation

# 初始化
ip_location = IpLocation('./db/qqwry.dat', './db/ipv6wry.db')

# 查询 IPv4 地址
result = ip_location.get_location('163.177.65.160')
print(result)

# 查询 IPv6 地址
result = ip_location.get_location('2400:3200:baba::1')
print(result)

# 关闭资源
ip_location.close()
```

### 5. 示例输出
#### 查询 IPv4 地址
```json
{
  "ip": "163.177.65.160",
  "country": "中国",
  "area": "中国广东省深圳市腾讯计算机系统联通节点"
}
```

#### 查询 IPv6 地址
```json
{
  "ip": "2400:3200:baba::1",
  "country": "中国",
  "area": "中国浙江杭州市 阿里云计算有限公司"
}
```

---

## 文件结构
```
.
├── db/                  # 数据库文件目录
│   ├── qqwry.dat        # IPv4 数据库文件
│   └── ipv6wry.db       # IPv6 数据库文件
├── ip_location_query.py # 主脚本文件
└── README.md            # 说明文档
```

---

## 注意事项
1. 确保数据库文件路径正确。
2. 数据库文件需要定期更新，以获取最新的 IP 归属地信息。
3. 脚本仅支持 Python 3.x 版本。

---

## 贡献与反馈
如果您有任何问题或建议，欢迎提交 Issue 或 Pull Request。

---

## 许可证
本项目基于 MIT 许可证开源。
