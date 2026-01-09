# IFLOW.md - RSA_GUI 项目上下文

## 项目概述

本项目是一个基于 Python 的 RSA 加密图形界面应用程序，使用 Slint UI 框架构建现代化的桌面界面。项目正处于早期开发阶段（版本 0.1.0），核心功能包括 RSA 密钥生成、加密和解密操作。

**主要技术栈：**
- Python 3.13+
- Slint UI 框架（声明式 UI）
- Cryptography 库（加密操作）

---

## 项目结构

```
RSA_GUI/
├── main.py           # 应用程序入口点
├── rsaa.py           # RSA 加密核心类
├── app-window.slint  # Slint UI 定义文件
├── test.py           # RSA 加密测试脚本
├── pyproject.toml    # Poetry 项目配置
├── README.md         # 项目说明文档
├── remember.md       # 环境配置备注
└── .venv/            # Python 虚拟环境
```

---

## 关键文件说明

### 核心文件

| 文件 | 用途 |
|------|------|
| `main.py` | 应用入口，初始化 Slint 窗口 |
| `rsaa.py` | RSA_plain 类，实现密钥生成、加密、解密 |
| `app-window.slint` | Slint 声明式 UI 定义 |

### 配置文件

| 文件 | 用途 |
|------|------|
| `pyproject.toml` | Poetry 依赖管理配置 |
| `.python-version` | 指定 Python 版本 |

### 测试文件

| 文件 | 用途 |
|------|------|
| `test.py` | RSA 加密/解密的命令行测试 |

---

## 构建与运行

### 环境准备

```powershell
# 激活虚拟环境
.venv\Scripts\activate

# 安装依赖
pip install -e .
```

### 运行应用

```powershell
python main.py
```

### 运行测试

```powershell
python test.py
```

---

## 开发指南

### 代码风格

- 使用类封装 RSA 功能（参见 `rsaa.py`）
- 遵循 Python PEP 8 规范
- 使用类型注解（推荐）

### 关键开发任务

1. **完善 UI 功能** - 当前 `app-window.slint` 仅包含简单的计数器示例，需要集成 RSA 操作界面
2. **实现文件交互** - 支持从文件导入/导出密钥和密文
3. **错误处理** - 添加输入验证和异常处理
4. **用户体验** - 添加状态提示、进度显示等

### 当前实现的 RSA 功能

`rsaa.py` 中的 `RSA_plain` 类提供：

- `generate_keys()` - 生成 2048 位 RSA 密钥对
- `encrypt(plaintext)` - 使用 OAEP+SHA256 加密
- `decrypt(ciphertext)` - 使用 OAEP+SHA256 解密

### 依赖版本要求

| 包 | 最低版本 |
|----|----------|
| Python | 3.13 |
| cryptography | 46.0.3 |
| slint | 1.14.1b1 |

---

## 注意事项

- 项目使用 Poetry 管理依赖
- Slint 需要在 Windows 上正确配置 PATH（参见 `remember.md`）
- 当前版本为原型阶段，代码结构可能随开发迭代调整
