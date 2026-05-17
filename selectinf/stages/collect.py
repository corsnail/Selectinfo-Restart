"""Collect Stage — encapsulates asset collection from multiple tools."""

import os
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, wait
from typing import List

from selectinf import get_logger
from selectinf.collect.dnsgrep import get_unique_domains
from selectinf.collect.extract_domains import extract_all_domains
from selectinf.core.config import PipelineConfig, ToolConfig
from selectinf.core.tool_runner import run_pipe_tool, run_tool
from selectinf.output.sqlite_manager import save_asset, save_final_domain, save_module_result
from selectinf.process.deduplicate import deduplicate_domains, deduplicate_url
from selectinf.process.url_converter import write_urls_to_domains_file
from selectinf.stages.base import PipelineStage, StageResult

logger = get_logger("stages.collect")


class CollectStage(PipelineStage):
    """Stage 1: Asset Collection.

    Runs subfinder, amass, OneForAll, massdns, ksubdomain in parallel groups,
    extracts domains, deduplicates, converts URLs, and iterates with JSFinder.
    """

    TOOLS = ["subfinder", "amass", "OneForAll", "massdns", "ksubdomain", "jsfinder"]

    def __init__(self, config: PipelineConfig):
        self.config = config

    def execute(self, task_id: int, input_path: str) -> StageResult:
        """Execute the collect stage for a given target domain.

        Args:
            task_id: The DB task ID.
            input_path: The target domain string (e.g., "example.com").

        Returns:
            StageResult with status, counts, and output path.
        """
        domain = input_path
        work_path = os.path.join(self.config.work_dir, str(task_id))
        os.makedirs(work_path, exist_ok=True)

        errors: List[str] = []

        # 1. Run all collection tools
        self._run_collection_tools(domain, work_path, errors)

        # 2. Save raw module outputs to DB (legacy table)
        self._save_module_results(task_id, domain, work_path)

        # 3. Extract domains from tool outputs
        try:
            extract_all_domains(domain, work_path)
        except Exception as e:
            logger.error("[extract_domains] 失败: %s", e, exc_info=True)
            errors.append(str(e))

        # 4. DNS discovery (dnsgrep)
        try:
            get_unique_domains(domain, work_path)
        except Exception as e:
            logger.error("[dnsgrep] DNS 发现失败: %s", e, exc_info=True)
            errors.append(str(e))

        # 5. Deduplicate merged domain list
        domain_txt = os.path.join(work_path, f"{domain}.txt")
        if os.path.exists(domain_txt):
            deduplicate_domains(domain_txt)
        else:
            logger.warning("[%s] 文件不存在，跳过去重", domain_txt)

        # 6. Copy to domain_{domain}.txt (pre-JSFinder baseline)
        domain_file = os.path.join(work_path, f"domain_{domain}.txt")
        if os.path.exists(domain_txt):
            with open(domain_txt, "r", encoding="utf-8") as f:
                content = f.read()
            with open(domain_file, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("域名已保存到 %s", domain_file)
        else:
            logger.warning("[%s] 文件不存在，跳过复制到 %s", domain_txt, domain_file)

        # 7. Convert domains → URLs (overwrites domain.txt in-place)
        if os.path.exists(domain_txt):
            write_urls_to_domains_file(domain_txt)
        else:
            logger.warning("[%s] 文件不存在，跳过 URL 转换", domain_txt)

        # 8. JSFinder iteration loop
        max_iterations = self._get_jsfinder_max_iterations()
        self._jsfinder_loop(domain, work_path, max_iterations, errors)

        # 9. Save final results to legacy + new tables
        total = self._save_final_results(task_id, domain, work_path)
        self._save_assets(task_id, domain, work_path)

        # 10. Copy final outputs to output_dir
        output_path = self._copy_final_outputs(domain, work_path)

        items_output = total if total > 0 else self._count_lines(output_path)

        return StageResult(
            status="success" if not errors else "partial",
            items_processed=items_output,
            items_output=items_output,
            errors=errors,
            output_path=output_path,
        )

    # ------------------------------------------------------------------
    # 1. Tool runners (mirroring run.py logic, but with work_path)
    # ------------------------------------------------------------------

    def _run_collection_tools(self, domain: str, work_path: str, errors: List[str]) -> None:
        """Run subfinder, then amass+OneForAll and massdns+ksubdomain in parallel."""
        cfg = self.config.collect

        # subfinder first (sequential)
        if cfg.get("subfinder", ToolConfig()).enabled:
            self._subfinder_scan(domain, work_path)

        # Thread 1: amass + OneForAll
        def thread1():
            if cfg.get("amass", ToolConfig()).enabled:
                self._amass_scan(domain, work_path)
            if cfg.get("oneforall", ToolConfig()).enabled:
                self._oneforall_scan(domain, work_path)

        # Thread 2: massdns + ksubdomain
        def thread2():
            if cfg.get("massdns", ToolConfig()).enabled:
                self._massdns_scan(domain, work_path)
            if cfg.get("ksubdomain", ToolConfig()).enabled:
                self._ksubdomain_scan(domain, work_path)

        t1 = threading.Thread(target=thread1)
        t2 = threading.Thread(target=thread2)
        t1.start()
        logger.debug("线程1 已启动 (amass + OneForAll)")
        t2.start()
        logger.debug("线程2 已启动 (massdns + ksubdomain)")

        t1.join()
        t2.join()
        logger.info("所有扫描线程已完成")

    def _subfinder_scan(self, domain: str, work_path: str) -> None:
        logger.info("启动 subfinder 扫描: %s", domain)
        out = os.path.join(work_path, "subfinder.txt")
        run_tool(
            ["tools/subfinder/subfinder.exe", "-d", domain, "-o", out, "-silent"],
            description="subfinder",
            timeout=self.config.collect.get("subfinder", ToolConfig()).timeout,
        )

    def _amass_scan(self, domain: str, work_path: str) -> None:
        logger.info("启动 amass 扫描: %s", domain)
        out = os.path.join(work_path, "amass.txt")
        run_tool(
            ["tools/amass/amass.exe", "enum", "-v", "-src", "-ip", "-brute",
             "-d", domain, "-timeout", "20", "-active", "-o", out],
            description="amass",
            timeout=self.config.collect.get("amass", ToolConfig()).timeout,
        )

    def _oneforall_scan(self, domain: str, work_path: str) -> None:
        logger.info("启动 OneForAll 扫描: %s", domain)
        oneforall_dir = "engines/OneForAll"
        oneforall_abs = os.path.abspath(oneforall_dir)
        env = os.environ.copy()
        env["PYTHONPATH"] = oneforall_abs + os.pathsep + env.get("PYTHONPATH", "")

        # Dependency pre-check (best-effort)
        try:
            import importlib.util
            for pkg in ["fire", "loguru", "requests", "aiohttp"]:
                if importlib.util.find_spec(pkg) is None:
                    logger.warning(
                        "[OneForAll] 依赖包可能未安装: %s", pkg
                    )
        except Exception:
            pass

        result = run_tool(
            [sys.executable, "oneforall.py", "--target", domain, "run"],
            description="OneForAll",
            cwd=oneforall_dir,
            env=env,
            timeout=self.config.collect.get("oneforall", ToolConfig()).timeout,
        )
        if result and not result.success:
            stderr = result.stderr.strip() if result.stderr else ""
            stdout = result.stdout.strip() if result.stdout else ""
            logger.error("[OneForAll] 失败:\n%s", stderr)
            if stdout:
                logger.info("[OneForAll] STDOUT:\n%s", stdout)

    def _massdns_scan(self, domain: str, work_path: str) -> None:
        logger.info("启动 massdns 扫描: %s", domain)
        import platform

        system = platform.system()
        massdns_bin = (
            "tools/massdns/bin/massdns.exe"
            if system == "Windows"
            else "tools/massdns/bin/massdns"
        )

        if not os.path.exists(massdns_bin):
            logger.error(
                "[massdns] 可执行文件不存在: %s", massdns_bin
            )
            return

        subbrute_script = "tools/massdns/scripts/subbrute.py"
        names_file = "tools/massdns/lists/names.txt"
        resolvers_file = "tools/massdns/lists/resolvers.txt"

        for f in [subbrute_script, names_file, resolvers_file]:
            if not os.path.exists(f):
                logger.error("[massdns] 依赖文件缺失: %s", f)
                return

        massdns_out = os.path.join(work_path, "massdns.txt")
        result = run_pipe_tool(
            cmd1=[sys.executable, subbrute_script, names_file, domain],
            cmd2=[massdns_bin, "-r", resolvers_file, "-t", "A", "-o", "S", "-w", massdns_out],
            description="massdns",
            timeout=self.config.collect.get("massdns", ToolConfig()).timeout,
        )
        if result:
            if result.stdout:
                logger.info("[massdns] 完成\n[STDOUT]\n%s", result.stdout)
            else:
                logger.info("[massdns] 完成")
            if result.stderr and result.stderr.strip():
                if result.exit_code != 0:
                    logger.error("[massdns] 失败 (exit=%d)\n[STDERR]\n%s", result.exit_code, result.stderr.strip())
                else:
                    logger.warning("[massdns] STDERR:\n%s", result.stderr.strip())

    def _ksubdomain_scan(self, domain: str, work_path: str) -> None:
        logger.info("启动 ksubdomain 扫描: %s", domain)
        out = os.path.join(work_path, "ksubdomain.txt")
        run_tool(
            ["tools/ksubdomain/ksubdomain.exe", "-d", domain, "-b", "20M", "-o", out],
            description="ksubdomain",
            timeout=self.config.collect.get("ksubdomain", ToolConfig()).timeout,
        )

    # ------------------------------------------------------------------
    # 2. JSFinder loop (replicates run.py behaviour with work_dir isolation)
    # ------------------------------------------------------------------

    def _get_jsfinder_max_iterations(self) -> int:
        js_cfg = self.config.collect.get("jsfinder", ToolConfig())
        return js_cfg.extra.get("max_iterations", 5)

    def _jsfinder(self, url: str, cwd: str) -> None:
        """Run JSFinder for a single URL inside *cwd* so outputs land in work_dir."""
        logger.debug("JSFinder: %s", url)
        run_tool(
            [sys.executable, "tools/jsfinder/JSFinder.py", "-u", url,
             "-ou", "url.txt", "-os", "subdomain.txt"],
            description="JSFinder",
            cwd=cwd,
            timeout=self.config.collect.get("jsfinder", ToolConfig()).timeout,
        )

    def _jsfinder_loop(self, domain: str, work_path: str, max_iterations: int, errors: List[str]) -> None:
        """Iteratively run JSFinder until file size stabilises or max iterations reached."""
        domain_txt = os.path.join(work_path, f"{domain}.txt")
        visited_urls = set()
        last_size = -1
        iteration = 0

        while iteration < max_iterations:
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
                    url = line.strip()
                    if url and url not in visited_urls:
                        self._jsfinder(url, cwd=work_path)
                        visited_urls.add(url)
                        subdomain_path = os.path.join(work_path, "subdomain.txt")
                        if os.path.exists(subdomain_path):
                            deduplicate_domains(subdomain_path)
                        if os.path.exists(domain_txt):
                            deduplicate_url(domain_txt)

            # Merge subdomain.txt into domain_{domain}.txt
            subdomain_path = os.path.join(work_path, "subdomain.txt")
            if os.path.exists(subdomain_path):
                with open(subdomain_path, "r", encoding="utf-8") as f:
                    content = f.read()
                domain_file = os.path.join(work_path, f"domain_{domain}.txt")
                with open(domain_file, "a", encoding="utf-8") as f:
                    f.write(content)

                write_urls_to_domains_file(subdomain_path)
                with open(domain_txt, "a", encoding="utf-8") as f:
                    with open(subdomain_path, "r", encoding="utf-8") as f2:
                        for line in f2:
                            f.write(line)
                try:
                    os.remove(subdomain_path)
                except OSError:
                    pass

            domain_file = os.path.join(work_path, f"domain_{domain}.txt")
            if os.path.exists(domain_file):
                deduplicate_domains(domain_file)
            if os.path.exists(domain_txt):
                deduplicate_url(domain_txt)

    # ------------------------------------------------------------------
    # 3. Persistence helpers (legacy + new tables)
    # ------------------------------------------------------------------

    def _save_module_results(self, task_id: int, domain: str, work_path: str) -> None:
        modules = {
            "subfinder": os.path.join(work_path, "subfinder.txt"),
            "amass": os.path.join(work_path, "amass.txt"),
            "OneForAll": f"engines/OneForAll/results/{domain}.csv",
            "massdns": os.path.join(work_path, "massdns.txt"),
            "ksubdomain": os.path.join(work_path, "ksubdomain.txt"),
        }

        for module_name, output_file in modules.items():
            if os.path.exists(output_file):
                domain_count = self._count_lines(output_file)
                raw_output = self._read_file(output_file)
                save_module_result(
                    task_id=task_id,
                    module_name=module_name,
                    output_file=output_file,
                    raw_output=raw_output[:5000],
                    domain_count=domain_count,
                    status="success",
                )
            else:
                save_module_result(
                    task_id=task_id,
                    module_name=module_name,
                    status="failed",
                    error_msg=f"输出文件不存在: {output_file}",
                )

        # dnsgrep result
        dns_file = os.path.join(work_path, f"{domain}.txt")
        if os.path.exists(dns_file):
            count = self._count_lines(dns_file)
            save_module_result(
                task_id=task_id,
                module_name="dnsgrep",
                output_file=dns_file,
                domain_count=count,
                status="success",
            )

    def _save_final_results(self, task_id: int, domain: str, work_path: str) -> int:
        """Save final domains to legacy final_results table. Returns total count."""
        final_file = os.path.join(work_path, f"domain_{domain}.txt")
        url_file = os.path.join(work_path, f"{domain}.txt")
        total = 0

        if os.path.exists(final_file):
            with open(final_file, "r", encoding="utf-8") as f:
                for line in f:
                    d = line.strip()
                    if d:
                        save_final_domain(task_id, domain=d, source_module="final")
                        total += 1

        if os.path.exists(url_file):
            with open(url_file, "r", encoding="utf-8") as f:
                for line in f:
                    url = line.strip()
                    if url:
                        save_final_domain(task_id, domain=url, source_module="url_converter")
                        total += 1

        logger.info("[SQLite] 最终域名已入库: %d 条", total)
        return total

    def _save_assets(self, task_id: int, domain: str, work_path: str) -> None:
        """Populate the new assets table (dual-write)."""
        final_file = os.path.join(work_path, f"domain_{domain}.txt")
        if not os.path.exists(final_file):
            return

        with open(final_file, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip()
                if d:
                    save_asset(task_id, domain=d, source_module="collect")

    # ------------------------------------------------------------------
    # 4. File utilities
    # ------------------------------------------------------------------

    def _copy_final_outputs(self, domain: str, work_path: str) -> str:
        """Copy domain_{domain}.txt and {domain}.txt to output_dir."""
        os.makedirs(self.config.output_dir, exist_ok=True)

        src_domain = os.path.join(work_path, f"domain_{domain}.txt")
        dst_domain = os.path.join(self.config.output_dir, f"domain_{domain}.txt")
        if os.path.exists(src_domain):
            shutil.copy2(src_domain, dst_domain)
            logger.info("复制最终域名文件: %s → %s", src_domain, dst_domain)
        else:
            logger.warning("源文件不存在，跳过复制: %s", src_domain)

        src_url = os.path.join(work_path, f"{domain}.txt")
        dst_url = os.path.join(self.config.output_dir, f"{domain}.txt")
        if os.path.exists(src_url):
            shutil.copy2(src_url, dst_url)
            logger.info("复制 URL 文件: %s → %s", src_url, dst_url)
        else:
            logger.warning("源文件不存在，跳过复制: %s", src_url)

        return dst_domain

    @staticmethod
    def _count_lines(filepath: str) -> int:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    @staticmethod
    def _read_file(filepath: str) -> str:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""
