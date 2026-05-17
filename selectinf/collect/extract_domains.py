import re
import csv
import subprocess
import sys
import os
from selectinf import get_logger

logger = get_logger("collect.extract_domains")


def extract_domain_ksubdomain(url, work_dir="."):
    ksubdomain_path = os.path.join(work_dir, "ksubdomain.txt")
    try:
        with open(ksubdomain_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logger.warning("ksubdomain.txt 不存在，跳过")
        return

    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", content)

    output_file = os.path.join(work_dir, url + ".txt")

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")
    logger.info("ksubdomain → %s (%d 条)", output_file, len(domains))

    os.remove(ksubdomain_path)
    logger.debug("已删除 %s", ksubdomain_path)


def extract_domain_massdns(url, work_dir="."):
    massdns_path = os.path.join(work_dir, "massdns.txt")
    try:
        with open(massdns_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logger.warning("massdns.txt 不存在，跳过")
        return

    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", content)

    output_file = os.path.join(work_dir, url + ".txt")

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")
    logger.info("massdns → %s (%d 条)", output_file, len(domains))

    os.remove(massdns_path)
    logger.debug("已删除 %s", massdns_path)


def extract_domain_amass(url, work_dir="."):
    amass_path = os.path.join(work_dir, "amass.txt")
    try:
        with open(amass_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logger.warning("amass.txt 不存在，跳过")
        return

    domains = content.split("\n")

    output_file = os.path.join(work_dir, url + ".txt")

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            if domain.strip():
                f.write(domain + "\n")

    logger.info("amass → %s (%d 条)", output_file, len(domains))

    os.remove(amass_path)
    logger.debug("已删除 %s", amass_path)


def extract_domain_subfinder(url, work_dir="."):
    subfinder_path = os.path.join(work_dir, "subfinder.txt")
    try:
        with open(subfinder_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logger.warning("subfinder.txt 不存在，跳过")
        return

    domains = content.split("\n")

    output_file = os.path.join(work_dir, url + ".txt")

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            if domain.strip():
                f.write(domain + "\n")

    logger.info("subfinder → %s (%d 条)", output_file, len(domains))

    os.remove(subfinder_path)
    logger.debug("已删除 %s", subfinder_path)


def extract_domain_OneForAll(url, work_dir="."):
    csv_file = r"engines\OneForAll\results\{}.csv".format(url)
    txt_file = os.path.join(work_dir, url + ".txt")

    domain_list = []

    try:
        with open(csv_file, "r", encoding="gbk") as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    url_val = row[0]
                    domain = re.findall(r"https?://([^\s/$.?#].[^\s]*)", url_val)
                    if domain:
                        domain_list.append(domain[0])
    except FileNotFoundError:
        logger.warning("OneForAll CSV 不存在: %s", csv_file)
        return

    with open(txt_file, "a", encoding="utf-8") as file:
        for domain in domain_list:
            file.write(domain + "\n")

    logger.info("OneForAll → %s (%d 条)", txt_file, len(domain_list))

    os.remove(csv_file)
    logger.debug("已删除 %s", csv_file)


def extract_all_domains(url, work_dir="."):
    """从所有工具输出文件中提取域名并合并到 {url}.txt"""
    logger.info("开始提取域名: %s", url)
    try:
        extract_domain_subfinder(url, work_dir)
        extract_domain_ksubdomain(url, work_dir)
        extract_domain_massdns(url, work_dir)
        extract_domain_amass(url, work_dir)
        extract_domain_OneForAll(url, work_dir)
    except Exception as e:
        logger.error("域名提取失败: %s", e, exc_info=True)

    output_file = os.path.join(work_dir, url + ".txt")
    logger.info("域名已提取并保存到 %s", output_file)


if __name__ == "__main__":
    url = sys.argv[1]
    extract_all_domains(url)
