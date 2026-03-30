import re
import os
import json
import argparse
import shutil
import time
import csv
import subprocess
import sys
from collections import deque, defaultdict
from urllib.parse import urlparse, urljoin

# ==================== 配置区 ====================
DEFAULT_SCAN_DIR = "js_files"
OUTPUT_CSV = "results/leak_results.csv"          # 统一 CSV 输出文件（默认放入 results 文件夹）
SHOW_CONTEXT_LINES = 2
DOWNLOAD_DELAY = 1
SCAN_IO_DELAY = 2
CURL_TIMEOUT = 30
API_OUTPUT_FILE = "results/api_paths.txt"        # API 路径单独输出（默认放入 results 文件夹）

# ==================== 正则模式（基础敏感信息） ====================
BASE_PATTERNS = {
    "aws_access_key": re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', re.IGNORECASE),
    "aws_secret_key": re.compile(r'(?:aws|AWS)_?secret[_\-]?access[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
                                 re.IGNORECASE),
    "private_key": re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----', re.IGNORECASE),
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
    "api_key": re.compile(r'(?:api[_-]?key|apikey|api_token|apikey)\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE),
    "token": re.compile(r'(?:token|access_token|bearer|auth_token|jwt_token)\s*[=:]\s*["\']([^"\']{16,})["\']',
                        re.IGNORECASE),
    "password": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', re.IGNORECASE),
    "sentry_dsn": re.compile(r'dsn\s*:\s*["\'](https://[^"\']+@[^"\']+/\d+)["\']', re.IGNORECASE),
    "github_token": re.compile(r'gh[psu]_[A-Za-z0-9_]{36,255}', re.IGNORECASE),
    "slack_token": re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,48}', re.IGNORECASE),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}', re.IGNORECASE),
    "generic_secret": re.compile(r'(?:secret|private_key|client_secret)\s*[=:]\s*["\']([^"\']{16,})["\']',
                                 re.IGNORECASE),
    "internal_ip_url": re.compile(
        r'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)[/"]?'),
    "internal_ip": re.compile(
        r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)'),
    "dynamic_script": re.compile(r'(createElement\([\'"]script[\'"]\)|setAttribute\([\'"]src[\'"]|\.src\s*=)'),
    "eval": re.compile(r'\beval\s*\('),
    "function": re.compile(r'\bnew\s+Function\s*\('),
    "innerHTML": re.compile(r'\.innerHTML\s*='),
    "dangerous_property": re.compile(r'(document\.write|document\.writeln)'),
}

# ==================== 扩展泄露检测模式（深度扫描） ====================
EXTRA_PATTERNS = {
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "phone_cn": re.compile(r'1[3-9]\d{9}'),
    "id_card": re.compile(r'[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]'),
    "mysql_conn": re.compile(r'mysql:\/\/[^\s"\']+'),
    "postgres_conn": re.compile(r'postgresql:\/\/[^\s"\']+'),
    "mongodb_conn": re.compile(r'mongodb:\/\/[^\s"\']+'),
    "redis_conn": re.compile(r'redis:\/\/[^\s"\']+'),
    "s3_bucket": re.compile(r's3://[a-zA-Z0-9\-._]+'),
    "azure_storage": re.compile(r'azure://[^\s"\']+|\.blob\.core\.windows\.net'),
    "internal_domain": re.compile(
        r'([a-zA-Z0-9\-]+\.)?(corp|internal|local|lan|dev|test|staging|prod)\.(com|net|org|local)'),
    "abs_path": re.compile(
        r'(?:[A-Za-z]:\\|/)(?:[\w\-\.]+/)*[\w\-\.]+\.(?:js|json|xml|txt|log|conf|config|ini|properties)'),
    "git_repo": re.compile(r'git@[^\s]+|https?://[^\s]+\.git'),
    "base64_data": re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
    "comment_secret": re.compile(r'//\s*(?:TODO|FIXME|HACK|NOTE|BUG|SECRET|PASSWORD|KEY)\s*[:=]?\s*(.+)',
                                 re.IGNORECASE),
    "debug_log": re.compile(
        r'console\.(log|debug|info|warn|error)\s*\(\s*["\']([^"\']*(?:password|token|key|secret)[^"\']*)["\']',
        re.IGNORECASE),
}

# ==================== API 路径提取正则 ====================
API_PATTERNS = [
    re.compile(r"['\"`](/api[^'\"`\s]*)['\"`]", re.IGNORECASE),
    re.compile(r"['\"`](/v\d+/[^'\"`\s]*)['\"`]", re.IGNORECASE),
    re.compile(r"url\s*:\s*['\"`](/[^'\"`]*)['\"`]", re.IGNORECASE),
    re.compile(r"axios\.(?:get|post|put|delete|patch)\s*\(\s*['\"`]([^'\"`]*)['\"`]", re.IGNORECASE),
    re.compile(r"fetch\s*\(\s*['\"`]([^'\"`]*)['\"`]", re.IGNORECASE),
    re.compile(r"['\"`](/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)['\"`]"),
]


def is_likely_api_path(path):
    exclude_extensions = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf',
                          '.eot')
    if path.lower().endswith(exclude_extensions):
        return False
    if path.startswith('/static/') or path.startswith('/assets/') or path.startswith('/lib/'):
        return False
    return True


# ==================== 辅助函数 ====================
def get_line_context(lines_deque, target_line_num):
    context_parts = []
    for ln, l in lines_deque:
        prefix = ">>> " if ln == target_line_num else "    "
        context_parts.append(f"{prefix}{ln:4d}: {l}")
    return "\n".join(context_parts)


def scan_file(filepath, deep_scan=False, extract_api=False, quiet=False):
    """返回：基础泄露列表，扩展泄露列表，API路径集合"""
    findings = []  # 基础泄露
    extra_findings = []  # 扩展泄露
    api_paths = set()
    recent_lines = deque(maxlen=SHOW_CONTEXT_LINES)
    line_num = 0

    try:
        # 尝试多种编码
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
                    for raw_line in f:
                        line_num += 1
                        line = raw_line.rstrip('\n\r')
                        recent_lines.append((line_num, line))

                        # 基础敏感信息
                        for name, pattern in BASE_PATTERNS.items():
                            for match in pattern.finditer(line):
                                matched_text = match.group(0)
                                # 内网 IP URL 模式仅匹配含内网 IP 的 URL，直接接受
                                # 其他模式不过滤
                                if name == "internal_ip_url":
                                    # 直接匹配即可
                                    pass
                                # 对于 base64 数据，增加简单熵过滤
                                if name == "base64_data" and len(matched_text) < 40:
                                    continue
                                context = get_line_context(recent_lines, line_num)
                                findings.append({
                                    "type": name,
                                    "matched_text": matched_text,
                                    "line": line_num,
                                    "context": context
                                })

                        # 深度扫描
                        if deep_scan:
                            for name, pattern in EXTRA_PATTERNS.items():
                                for match in pattern.finditer(line):
                                    matched_text = match.group(0)
                                    if name == "base64_data" and len(matched_text) < 40:
                                        continue
                                    context = get_line_context(recent_lines, line_num)
                                    extra_findings.append({
                                        "type": name,
                                        "matched_text": matched_text,
                                        "line": line_num,
                                        "context": context
                                    })

                        # API 路径提取
                        if extract_api:
                            for pattern in API_PATTERNS:
                                for match in pattern.finditer(line):
                                    path = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                                    path = path.strip('"\'`')
                                    if path.startswith('/') and is_likely_api_path(path):
                                        api_paths.add(path)
                break  # 成功读取，退出编码循环
            except UnicodeDecodeError:
                continue
        else:
            # 所有编码都失败
            if not quiet:
                print(f"[!] 无法解码文件: {filepath}")
    except MemoryError:
        if not quiet:
            print(f"[!] 内存不足，跳过文件: {filepath}")
    except Exception as e:
        if not quiet:
            print(f"[!] 无法读取文件 {filepath}: {e}")
    return findings, extra_findings, api_paths


def save_results_to_csv_writer(output_csv, all_findings, all_extra, quiet=False):
    """将所有泄露（基础+扩展）保存到一个 CSV 文件，支持流式写入（增量）"""
    # 确保输出目录存在
    output_dir = os.path.dirname(output_csv)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # 以追加模式写入，但第一次调用需要写入表头
    # 此处为了简化，直接覆盖写入；因为调用一次后不再修改
    # 如果需要流式写入，可以在外部循环中每次调用此函数并传入追加模式
    # 但当前设计是全部扫描完再写入，为保持兼容，暂时不改为流式
    # 如果文件很大，可以改为流式写入，但影响不大
    with open(output_csv, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['File', 'Type', 'Matched Text', 'Line', 'Context'])
        for filepath, items in all_findings.items():
            for item in items:
                writer.writerow([filepath, item['type'], item['matched_text'], item['line'], item['context']])
        for filepath, items in all_extra.items():
            for item in items:
                writer.writerow([filepath, item['type'], item['matched_text'], item['line'], item['context']])
    if not quiet:
        print(f"[+] 泄露结果已保存到 {output_csv}")


def save_js_files(scan_dir, target_dir, quiet=False):
    """复制 JS 文件到指定目录，保持目录结构"""
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    for root, _, files in os.walk(scan_dir):
        for file in files:
            if file.endswith('.js'):
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, scan_dir)
                dst_path = os.path.join(target_dir, rel_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
                if not quiet:
                    print(f"[*] 已保存: {dst_path}")
    if not quiet:
        print(f"[+] 所有 JS 文件已保存到 {target_dir}")


def fetch_js_files(urls_file, target_dir, delay=1, base_url=None, quiet=False):
    """下载 JS 文件，保持 URL 路径结构"""
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # 检查 curl 命令
    try:
        subprocess.run(['curl', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] 错误：系统未安装 curl 或 curl 不可用。请安装 curl 或使用其他方法下载 JS 文件。")
        sys.exit(1)

    with open(urls_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    total = len(urls)
    if not quiet:
        print(f"[*] 准备下载 {total} 个 JS 文件，延迟 {delay} 秒/次")

    for idx, url in enumerate(urls, 1):
        try:
            # 补全 URL
            if base_url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url.rstrip('/') + '/', url.lstrip('/'))
                if not quiet:
                    print(f"    补全后URL: {url}")

            # 校验 URL 格式
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                if not quiet:
                    print(f"[!] 跳过无效 URL: {url}")
                continue

            # 保持路径结构：去掉开头的斜杠，保留目录层级
            rel_path = parsed.path.lstrip('/')
            if not rel_path.endswith('.js'):
                rel_path += '.js'
            # 防止路径遍历攻击，确保路径安全
            safe_rel_path = os.path.normpath(rel_path).lstrip(os.sep)
            if safe_rel_path.startswith('..'):
                # 存在路径遍历风险，跳过
                if not quiet:
                    print(f"[!] 不安全路径，跳过: {safe_rel_path}")
                continue
            save_path = os.path.join(target_dir, safe_rel_path)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            if not quiet:
                print(f"[{idx}/{total}] 下载: {url} -> {save_path}")

            cmd = ['curl', '-k', '-L', '-s', '-o', save_path, '--max-time', str(CURL_TIMEOUT), url]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                if not quiet:
                    print(f"    [!] curl 错误: {result.stderr}")
            elif not quiet:
                print(f"    成功保存")
        except Exception as e:
            if not quiet:
                print(f"    [!] 下载失败: {e}")
        time.sleep(delay)

    if not quiet:
        print(f"[+] 下载完成，文件保存至 {target_dir}")


def save_api_paths(all_api_paths, output_file, quiet=False):
    """保存 API 路径列表到文件"""
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    unique_paths = sorted(set(all_api_paths))
    with open(output_file, 'w', encoding='utf-8') as f:
        for path in unique_paths:
            f.write(path + '\n')
    if not quiet:
        print(f"[+] 共发现 {len(unique_paths)} 个 API 路径，已保存至 {output_file}")


# ==================== 扫描核心 ====================
def perform_scan(scan_dir, deep_scan, extract_api, output_csv, api_output, io_delay, quiet, fail_on_leak):
    if not os.path.isdir(scan_dir):
        if not quiet:
            print(f"[!] 目录不存在: {scan_dir}")
        return

    # 统计文件总数
    total_files = 0
    for root, _, files in os.walk(scan_dir):
        for file in files:
            if file.endswith('.js'):
                total_files += 1

    all_findings = defaultdict(list)
    all_extra = defaultdict(list)
    all_api_paths = set()
    processed = 0

    # 用于流式写入的 CSV writer 初始化（可选）
    # 这里为了简单，依然先收集再写入，但为了避免内存过大，可改为流式写入
    # 考虑到结果通常不会太大，暂时保持原样

    for root, _, files in os.walk(scan_dir):
        for file in files:
            if not file.endswith('.js'):
                continue
            processed += 1
            filepath = os.path.join(root, file)
            if not quiet:
                print(f"[*] 扫描 ({processed}/{total_files}): {filepath}")
            findings, extra, apis = scan_file(filepath, deep_scan=deep_scan, extract_api=extract_api, quiet=quiet)

            if findings:
                all_findings[filepath] = findings
                if not quiet:
                    print(f"[+] {filepath} 发现 {len(findings)} 个基础泄露")
                    for f in findings[:3]:
                        print(f"    [{f['type']}] {f['matched_text']} (行 {f['line']})")
                    if len(findings) > 3:
                        print(f"    ... 还有 {len(findings) - 3} 个")

            if extra:
                all_extra[filepath] = extra
                if not quiet:
                    print(f"[+] {filepath} 发现 {len(extra)} 个扩展泄露")
                    for e in extra[:3]:
                        print(f"    [{e['type']}] {e['matched_text']} (行 {e['line']})")
                    if len(extra) > 3:
                        print(f"    ... 还有 {len(extra) - 3} 个")

            if apis:
                all_api_paths.update(apis)
                if not quiet:
                    print(f"    [API] 新增 {len(apis)} 个路径")

            if io_delay > 0:
                time.sleep(io_delay)

    # 保存泄露结果到 CSV
    save_results_to_csv_writer(output_csv, all_findings, all_extra, quiet)

    # 保存 API 路径（如果启用）
    if extract_api:
        save_api_paths(all_api_paths, api_output, quiet)

    total_base_leaks = sum(len(v) for v in all_findings.values())
    total_extra_leaks = sum(len(v) for v in all_extra.values())
    total_leaks = total_base_leaks + total_extra_leaks

    if not quiet:
        print(f"\n统计：")
        print(f"  - 基础泄露文件数: {len(all_findings)}")
        if deep_scan:
            print(f"  - 扩展泄露文件数: {len(all_extra)}")
        print(f"  - 总泄露条目数: {total_leaks}")
        if extract_api:
            print(f"  - API 路径数: {len(all_api_paths)}")

    # 退出码控制
    if fail_on_leak and total_leaks > 0:
        sys.exit(1)
    sys.exit(0)


# ==================== 主函数 ====================
def main():
    parser = argparse.ArgumentParser(description="JS 文件泄露扫描工具 - 下载与扫描，结果集中到 CSV")

    # 操作模式（互斥组）
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--download-only", action="store_true", help="仅下载 JS 文件，不扫描")
    mode_group.add_argument("--scan-only", action="store_true", help="仅扫描本地目录，不下载")

    # 基本参数
    parser.add_argument("-d", "--dir", default=DEFAULT_SCAN_DIR,
                        help=f"扫描目录或下载目标目录（默认: {DEFAULT_SCAN_DIR}）")
    parser.add_argument("-f", "--fetch", metavar="URLS_FILE", help="从文件读取 URL 列表并下载（每行一个 URL）")
    parser.add_argument("-b", "--base-url", default=None, help="基础 URL，用于补全相对路径（如 https://example.com）")
    parser.add_argument("--delay", type=float, default=DOWNLOAD_DELAY, help=f"下载延迟秒数（默认: {DOWNLOAD_DELAY}）")

    # 扫描选项
    parser.add_argument("--deep-scan", action="store_true",
                        help="启用深度扫描（邮箱、手机号、身份证、数据库连接、Base64、注释秘密等）")
    parser.add_argument("--extract-api", action="store_true", help="启用 API 路径提取功能")
    parser.add_argument("--io-delay", type=float, default=SCAN_IO_DELAY,
                        help=f"扫描每个文件后的延迟秒数（默认: {SCAN_IO_DELAY}）")

    # 输出选项
    parser.add_argument("-o", "--output", default=OUTPUT_CSV, help=f"输出 CSV 文件（默认: {OUTPUT_CSV}）")
    parser.add_argument("--api-output", default=API_OUTPUT_FILE, help=f"API 路径输出文件（默认: {API_OUTPUT_FILE}）")
    parser.add_argument("-s", "--save-js", metavar="SAVE_DIR", help="将所有 JS 文件复制到指定目录用于人工审查")

    # 控制选项
    parser.add_argument("-q", "--quiet", action="store_true", help="静默模式，减少输出")
    parser.add_argument("--fail-on-leak", action="store_true", help="发现泄露时退出码为 1，否则正常退出 0")

    args = parser.parse_args()

    # 确定操作模式
    download_only = args.download_only
    scan_only = args.scan_only
    fetch_and_scan = (args.fetch is not None) and not download_only

    # 执行下载（如果需要）
    if args.fetch:
        if scan_only:
            if not args.quiet:
                print("[!] 错误：--scan-only 模式下不能同时使用 -f。")
            sys.exit(1)
        fetch_js_files(args.fetch, args.dir, args.delay, base_url=args.base_url, quiet=args.quiet)
        if download_only:
            if not args.quiet:
                print("[*] 仅下载模式完成。")
            sys.exit(0)
        # 否则继续扫描（下载并扫描）

    # 执行扫描（如果不需要下载或已下载完成）
    if not download_only:
        perform_scan(args.dir, args.deep_scan, args.extract_api, args.output, args.api_output, args.io_delay,
                     args.quiet, args.fail_on_leak)

    # 额外保存 JS 文件（如果需要）
    if args.save_js:
        if not os.path.isdir(args.dir):
            if not args.quiet:
                print(f"[!] 目录不存在: {args.dir}，无法保存 JS 文件。")
        else:
            save_js_files(args.dir, args.save_js, args.quiet)


if __name__ == "__main__":
    main()