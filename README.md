# jsscan

一个用于扫描 JavaScript 文件中敏感信息泄露的 Python 工具。支持本地扫描、远程下载、深度检测、API 路径提取等功能，结果输出为 CSV 文件，便于分析和审计。

## 功能特性

- **基础泄露检测**  
  AWS 密钥、JWT、API Key、密码、内网 IP、危险函数（eval, innerHTML, document.write 等）

- **深度扫描**  
  邮箱、手机号、身份证号、数据库连接串（MySQL, PostgreSQL, MongoDB, Redis）、S3 存储桶、Azure 存储、Base64 长串、注释内容（TODO/FIXME/SECRET）、调试日志中的敏感信息

- **远程下载**  
  从 URL 列表批量下载 JS 文件，保持原始目录结构（如 `https://example.com/js/app.js` → `js_files/js/app.js`）

- **URL 补全**  
  支持相对路径，配合 `--base-url` 自动拼接成完整 URL

- **API 路径提取**  
  识别代码中的 API 端点（如 `/api/v1/users`），并单独输出为文件

- **统一 CSV 输出**  
  所有泄露信息集中在一个 CSV 文件中，包含文件路径、类型、匹配文本、行号、上下文，便于 Excel 或数据分析工具处理

- **保存 JS 副本**  
  可将扫描目录下的所有 JS 文件复制到指定位置，方便人工审查

## 环境要求

- Python 3.6 或更高版本
- curl（用于下载功能）

## 安装

```bash
git clone https://github.com/trifbxy/jsscan.git
cd jsscan
# 本工具仅使用 Python 标准库，无需安装第三方依赖
```

## 使用示例

### 1. 仅扫描本地目录

```bash
python jsscan.py -d /path/to/js_files --deep-scan
```

### 2. 仅下载 JS 文件（不扫描）

```bash
python jsscan.py -f urls.txt --download-only -d downloaded_js -b https://example.com
```

### 3. 下载并扫描（默认模式）

```bash
python jsscan.py -f urls.txt -d js_files --deep-scan --extract-api
```

### 4. 保存 JS 副本

```bash
python jsscan.py -d js_files -s backup_js
```

## 参数说明

| 参数              | 说明                                                   | 默认值             |
| ----------------- | ------------------------------------------------------ | ------------------ |
| `-d, --dir`       | 扫描目录或下载目标目录                                 | `js_files`         |
| `-f, --fetch`     | 包含 JS URL 的文件（每行一个 URL）                     | 无                 |
| `--download-only` | 仅下载，不扫描                                         | `False`            |
| `--scan-only`     | 仅扫描本地目录，不下载                                 | `False`            |
| `-b, --base-url`  | 基础 URL，用于补全相对路径（如 `https://example.com`） | 无                 |
| `--delay`         | 下载延迟（秒）                                         | `1`                |
| `--deep-scan`     | 启用深度扫描                                           | `False`            |
| `--extract-api`   | 提取 API 路径                                          | `False`            |
| `--io-delay`      | 扫描每个文件后的延迟（秒）                             | `2`                |
| `-o, --output`    | 输出 CSV 文件路径                                      | `leak_results.csv` |
| `--api-output`    | API 路径输出文件                                       | `api_paths.txt`    |
| `-s, --save-js`   | 将所有 JS 文件复制到指定目录                           | 无                 |

## 输出说明

### `leak_results.csv`

包含所有泄露信息的 CSV 文件，列如下：

| 列名           | 说明                                                    |
| -------------- | ------------------------------------------------------- |
| `File`         | 文件路径（相对于扫描目录）                              |
| `Type`         | 泄露类型（如 `aws_access_key`、`email`、`password` 等） |
| `Matched Text` | 匹配到的敏感内容                                        |
| `Line`         | 所在行号                                                |
| `Context`      | 上下文（前后几行代码，便于定位）                        |

### `api_paths.txt`（仅当启用 `--extract-api`）

每行一个 API 路径，已去重排序。例如：
```
/api/v1/users
/api/login
/admin/config
```

## 注意事项

- **curl 依赖**：下载功能依赖系统 `curl` 命令，请确保已安装。
- **误报处理**：正则匹配可能产生误报（尤其是 Base64 长串和通用 token），建议人工复核关键结果。
- **网络礼貌**：下载时请遵守目标网站的 `robots.txt` 及频率限制，设置合理的 `--delay`。
- **大文件扫描**：使用流式读取，内存占用较小，但上下文记录可能占用部分内存。
- **编码问题**：文件读取使用 `utf-8` 编码，忽略错误，部分特殊编码文件可能无法正确解析。

## 贡献指南

欢迎提交 Issue 和 Pull Request。请确保代码符合 PEP 8 规范，并为新功能添加适当的注释和文档。

## 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。
