# -*- coding: utf-8 -*-
import threading
import subprocess
import os
import sys
import re
from selectinf import get_logger
from selectinf.process.deduplicate import *
from selectinf.process.url_converter import *
from selectinf.process.filter_wildcard import *
from selectinf.collect.dnsgrep import *
from selectinf.output.arl_exporter import *
from selectinf.output import mysql_exporter as csvToDatabase
from selectinf.collect.extract_domains import extract_all_domains
from selectinf.output.sqlite_manager import (
    init_db, create_task, finish_task, save_module_result,
    save_final_domain, get_task_summary
)

logger = get_logger("run")


def sanitize_target(url: str) -> str:
    """Strip protocol, path, and port from user input to get bare domain."""
    # Remove protocol: https://x666.me/path → x666.me/path
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    # Remove path and query: x666.me/path?a=1 → x666.me
    url = url.split("/")[0]
    # Remove port: x666.me:8080 → x666.me
    url = url.split(":")[0]
    # Trim whitespace
    domain = url.strip().rstrip(".")
    if not domain:
        raise ValueError("Invalid input: could not extract domain")
    logger.info("目标域名: %s (原始输入已清洗)", domain)
    return domain


def _run_cmd(args, description="command", timeout=300, shell=False, cwd=None, env=None):
    """Run a subprocess safely with logging, timing, and detailed error context."""
    import time
    cmd_str = " ".join(args) if isinstance(args, list) else args
    logger.debug("[%s] 执行: %s", description, cmd_str)
    start = time.time()
    try:
        result = subprocess.run(
            args,
            shell=shell,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        elapsed = time.time() - start
        # 输出完整 stdout/stderr（不截断）
        stdout_full = result.stdout.strip() if result.stdout else ""
        stderr_full = result.stderr.strip() if result.stderr else ""

        if result.returncode != 0:
            # 特定错误识别（使用完整 stderr）
            if "wpcap.dll" in stderr_full or "couldn't load wpcap" in stderr_full:
                logger.error(
                    "[%s] 失败: 缺少 Npcap/WinPcap 运行库 (wpcap.dll)。"
                    "请安装 Npcap (https://npcap.com/) 或 WinPcap 后重试。",
                    description,
                )
            else:
                logger.error(
                    "[%s] 失败 (exit=%d, 耗时=%.1fs)\n[STDERR]\n%s",
                    description,
                    result.returncode,
                    elapsed,
                    stderr_full if stderr_full else "<no stderr>",
                )
            if stdout_full:
                logger.info("[%s] STDOUT:\n%s", description, stdout_full)
        else:
            if stdout_full:
                logger.info("[%s] 完成 (耗时=%.1fs)\n[STDOUT]\n%s", description, elapsed, stdout_full)
            else:
                logger.info("[%s] 完成 (耗时=%.1fs)", description, elapsed)
            if stderr_full:
                logger.warning("[%s] STDERR:\n%s", description, stderr_full)
        return result
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        logger.error("[%s] 超时 (%ds, 实际耗时=%.1fs)。建议: 增加超时时间或减少扫描范围。", description, timeout, elapsed)
        return None
    except FileNotFoundError as e:
        logger.error("[%s] 找不到可执行文件: %s。请确认工具已正确放置在 tools/ 目录。", description, e.filename if hasattr(e, 'filename') else args[0])
        return None
    except Exception as e:
        elapsed = time.time() - start
        logger.error("[%s] 执行异常 (%s, 耗时=%.1fs): %s", description, type(e).__name__, elapsed, e)
        return None


def oneforall_scan(domain):
    logger.info("启动 OneForAll 扫描: %s", domain)
    oneforall_dir = "engines/OneForAll"
    oneforall_abs = os.path.abspath(oneforall_dir)
    # 设置 PYTHONPATH 使 OneForAll 内部 import 正常工作
    env = os.environ.copy()
    env["PYTHONPATH"] = oneforall_abs + os.pathsep + env.get("PYTHONPATH", "")

    # 先检查 OneForAll 依赖是否安装
    try:
        import importlib.util
        for pkg in ["fire", "loguru", "requests", "aiohttp"]:
            if importlib.util.find_spec(pkg) is None:
                logger.warning("[OneForAll] 依赖包可能未安装: %s。建议: pip install -r engines/OneForAll/requirements.txt", pkg)
    except Exception:
        pass

    result = _run_cmd(
        [sys.executable, "oneforall.py", "--target", domain, "run"],
        description="OneForAll",
        cwd=oneforall_dir,
        env=env,
    )
    if result and result.returncode != 0:
        stderr_full = result.stderr.strip() if result.stderr else ""
        stdout_full = result.stdout.strip() if result.stdout else ""
        logger.error("[OneForAll] 完整错误输出:\n%s", stderr_full)
        if stdout_full:
            logger.info("[OneForAll] STDOUT:\n%s", stdout_full)


def massdns_scan(domain):
    logger.info("启动 massdns 扫描: %s", domain)
    import platform

    # 根据平台选择 massdns 可执行文件路径
    system = platform.system()
    if system == "Windows":
        massdns_bin = "tools/massdns/bin/massdns.exe"
    else:
        massdns_bin = "tools/massdns/bin/massdns"

    # 预检查文件是否存在
    if not os.path.exists(massdns_bin):
        logger.error(
            "[massdns] 可执行文件不存在: %s (当前平台=%s)。"
            "请从 https://github.com/blechschmidt/massdns 下载对应平台的二进制文件。",
            massdns_bin,
            system,
        )
        return

    subbrute_script = "tools/massdns/scripts/subbrute.py"
    names_file = "tools/massdns/lists/names.txt"
    resolvers_file = "tools/massdns/lists/resolvers.txt"

    for f in [subbrute_script, names_file, resolvers_file]:
        if not os.path.exists(f):
            logger.error("[massdns] 依赖文件缺失: %s", f)
            return

    try:
        proc1 = subprocess.Popen(
            [sys.executable, subbrute_script, names_file, domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        proc2 = subprocess.Popen(
            [massdns_bin, "-r", resolvers_file, "-t", "A", "-o", "S", "-w", "massdns.txt"],
            stdin=proc1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        proc1.stdout.close()
        _stdout, stderr = proc2.communicate(timeout=300)
        if proc2.returncode != 0:
            logger.error("[massdns] 失败 (exit=%d)\n[STDERR]\n%s", proc2.returncode, stderr.strip() if stderr else "")
        else:
            if _stdout:
                logger.info("[massdns] 完成\n[STDOUT]\n%s", _stdout)
            else:
                logger.info("[massdns] 完成")
            if stderr and stderr.strip():
                logger.warning("[massdns] STDERR:\n%s", stderr.strip())
    except subprocess.TimeoutExpired:
        logger.error("[massdns] 超时 (300s)")
        proc1.kill()
        proc2.kill()
    except FileNotFoundError as e:
        logger.error("[massdns] 找不到可执行文件: %s", e)


def subfinder_scan(domain):
    logger.info("启动 subfinder 扫描: %s", domain)
    _run_cmd(
        ["tools/subfinder/subfinder.exe", "-d", domain, "-o", "subfinder.txt", "-silent"],
        description="subfinder",
    )


def amass_scan(domain):
    logger.info("启动 amass 扫描: %s", domain)
    _run_cmd(
        ["tools/amass/amass.exe", "enum", "-v", "-src", "-ip", "-brute",
         "-d", domain, "-timeout", "20", "-active", "-o", "amass.txt"],
        description="amass",
        timeout=600,
    )


def ksubdomain_scan(domain):
    logger.info("启动 ksubdomain 扫描: %s", domain)
    _run_cmd(
        ["tools/ksubdomain/ksubdomain.exe", "-d", domain, "-b", "20M", "-o", "ksubdomain.txt"],
        description="ksubdomain",
    )


def scan_thread1(domain):
    amass_scan(domain)
    oneforall_scan(domain)


def scan_thread2(domain):
    massdns_scan(domain)
    ksubdomain_scan(domain)


def jsfinder(url):
    logger.debug("JSFinder: %s", url)
    _run_cmd(
        ["python", "tools/jsfinder/JSFinder.py", "-u", url, "-ou", "url.txt", "-os", "subdomain.txt"],
        description="JSFinder",
    )


# 主函数
def main():
    logger.info("=" * 50)
    logger.info("selectinf 资产收集框架启动")
    logger.info("=" * 50)

    # 初始化 SQLite 数据库
    init_db()

    raw_input = input("请输入URL: ")
    domain = sanitize_target(raw_input)

    # 创建任务记录
    task_id = create_task(domain)

    subfinder_scan(domain)

    threads = []
    t1 = threading.Thread(target=scan_thread1, args=(domain,))
    threads.append(t1)
    t1.start()
    logger.debug("线程1 已启动 (amass + OneForAll)")

    t2 = threading.Thread(target=scan_thread2, args=(domain,))
    threads.append(t2)
    t2.start()
    logger.debug("线程2 已启动 (massdns + ksubdomain)")

    for thread in threads:
        thread.join()
    logger.info("所有扫描线程已完成")

    # 保存各模块结果到数据库
    _save_module_results(task_id, domain)

    # 域名提取（直接函数调用，避免子进程 PYTHONPATH 问题）
    try:
        extract_all_domains(domain)
    except Exception as e:
        logger.error("[extract_domains] 失败: %s", e, exc_info=True)

    # DNS 发现
    try:
        get_unique_domains(domain)
    except Exception as e:
        logger.error("[dnsgrep] DNS 发现失败: %s", e, exc_info=True)

    # 去重与文件处理（带存在性检查）
    domain_txt = domain + ".txt"
    if os.path.exists(domain_txt):
        deduplicate_domains(domain_txt)
    else:
        logger.warning("[%s] 文件不存在，跳过去重", domain_txt)

    if os.path.exists(domain_txt):
        with open(domain_txt, "r", encoding="utf-8") as f:
            content = f.read()
        with open("domain_" + domain + ".txt", "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("域名已保存到 domain_%s.txt", domain)
    else:
        logger.warning("[%s] 文件不存在，跳过复制到 domain_%s.txt", domain_txt, domain)

    if os.path.exists(domain_txt):
        write_urls_to_domains_file(domain_txt)
    else:
        logger.warning("[%s] 文件不存在，跳过 URL 转换", domain_txt)

    visited_urls = set()
    last_size = -1
    iteration = 0
    while True:
        iteration += 1
        if not os.path.exists(domain_txt):
            logger.warning("[%s] 文件不存在，JSFinder 迭代终止", domain_txt)
            break

        size = os.path.getsize(domain_txt)
        if size == last_size:
            logger.info("JSFinder 迭代完成 (共 %d 轮)", iteration)
            break

        last_size = size
        with open(domain_txt, "r", encoding="utf-8") as f:
            for line in f:
                urls = line.strip()
                if urls and urls not in visited_urls:
                    jsfinder(urls)
                    visited_urls.add(urls)
                    if os.path.exists("subdomain.txt"):
                        deduplicate_domains("subdomain.txt")
                    if os.path.exists(domain_txt):
                        deduplicate_url(domain_txt)

        if os.path.exists(f"{domain}.txt"):
            with open(domain_txt, "a", encoding="utf-8") as f:
                with open(f"{domain}.txt", "r", encoding="utf-8") as f2:
                    for line in f2:
                        f.write(line)
            os.remove(f"{domain}.txt")

        if os.path.exists("subdomain.txt"):
            with open("subdomain.txt", "r", encoding="utf-8") as f:
                content = f.read()
            with open("domain_" + domain + ".txt", "a", encoding="utf-8") as f:
                f.write(content)

            write_urls_to_domains_file("subdomain.txt")
            with open(domain_txt, "a", encoding="utf-8") as f:
                with open("subdomain.txt", "r", encoding="utf-8") as f2:
                    for line in f2:
                        f.write(line)
            os.remove("subdomain.txt")

        deduplicate_domains("domain_" + domain + ".txt")
        if os.path.exists(domain_txt):
            deduplicate_url(domain_txt)

    logger.info("资产收集完成，开始导出...")

    # 保存最终去重后的域名到 SQLite
    total_domains = _save_final_results(task_id, domain)

    # ARL 导出
    domain_file = "domain_" + domain + ".txt"
    if os.path.exists(domain_file):
        try:
            add(domain)
            task_ids = task_id_search(f"{domain}")
            logger.info("获取到 %d 个任务 ID", len(task_ids))
            send_get_requests(task_ids)
            xlsx_to_csv(task_ids)
            remove_from_csv("output_file.csv", f"{domain}.csv")
        except Exception as e:
            logger.error("[ARL 导出] 失败: %s", e, exc_info=True)
    else:
        logger.warning("[%s] 文件不存在，跳过 ARL 导出", domain_file)

    # MySQL 数据库导入（原有逻辑）
    csv_file = f"{domain}.csv"
    if os.path.exists(csv_file):
        try:
            csvToDatabase.csvToDatabase(domain)
            logger.info("数据已导入 MySQL 数据库")
        except Exception as e:
            logger.error("[MySQL 导入] 失败: %s", e, exc_info=True)
    else:
        logger.warning("[%s] 文件不存在，跳过 MySQL 导入", csv_file)

    # 完成任务并输出摘要
    summary = get_task_summary(task_id)
    finish_task(task_id, total_subdomains=summary["total_unique_domains"])
    logger.info("[SQLite] 任务摘要: %s", summary)
    logger.info("selectinf 任务完成!")
    input("按任意键退出...")
    sys.exit(0)


def _count_lines(filepath):
    """统计文件行数"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def _read_file(filepath):
    """读取文件内容（限制大小）"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def _save_module_results(task_id, domain):
    """将各模块扫描结果保存到 SQLite"""
    modules = {
        "subfinder": "subfinder.txt",
        "amass": "amass.txt",
        "OneForAll": f"engines/OneForAll/results/{domain}.csv",
        "massdns": "massdns.txt",
        "ksubdomain": "ksubdomain.txt",
    }

    for module_name, output_file in modules.items():
        if os.path.exists(output_file):
            domain_count = _count_lines(output_file)
            raw_output = _read_file(output_file)
            save_module_result(
                task_id=task_id,
                module_name=module_name,
                output_file=output_file,
                raw_output=raw_output[:5000],  # 限制存储大小
                domain_count=domain_count,
                status="success"
            )
        else:
            save_module_result(
                task_id=task_id,
                module_name=module_name,
                status="failed",
                error_msg=f"输出文件不存在: {output_file}"
            )

    # 保存 dnsgrep 结果
    dns_file = f"{domain}.txt"
    if os.path.exists(dns_file):
        count = _count_lines(dns_file)
        save_module_result(
            task_id=task_id,
            module_name="dnsgrep",
            output_file=dns_file,
            domain_count=count,
            status="success"
        )


def _save_final_results(task_id, domain):
    """保存最终去重后的域名结果"""
    final_file = "domain_" + domain + ".txt"
    url_file = domain + ".txt"

    total = 0

    # 保存最终域名
    if os.path.exists(final_file):
        with open(final_file, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip()
                if d:
                    save_final_domain(task_id, domain=d, source_module="final")
                    total += 1

    # 保存 URL 转换结果（如果有）
    if os.path.exists(url_file):
        with open(url_file, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url:
                    save_final_domain(task_id, domain=url, source_module="url_converter")
                    total += 1

    logger.info("[SQLite] 最终域名已入库: %d 条", total)
    return total


if __name__ == "__main__":
    main()
