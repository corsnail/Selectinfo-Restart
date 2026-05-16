import os
from selectinf import get_logger

logger = get_logger("process.deduplicate")


def deduplicate_domains(file_name):
    if not os.path.exists(file_name):
        logger.warning("[去重] 文件不存在，跳过: %s", file_name)
        return
    with open(file_name, "r", encoding="utf-8") as f:
        domains = f.read().splitlines()

    domains = [domain.replace(" ", "") for domain in domains if domain.strip()]
    unique_domains = sorted(set(domains))

    with open(file_name, "w", encoding="utf-8") as f:
        for domain in unique_domains:
            f.write(domain + "\n")

    logger.info("域名去重: %s (%d → %d)", file_name,
                len(domains), len(unique_domains))


def deduplicate_url(filename):
    if not os.path.exists(filename):
        logger.warning("[URL去重] 文件不存在，跳过: %s", filename)
        return
    with open(filename, 'r', encoding="utf-8") as file:
        lines = [line.strip() for line in file.readlines() if line.strip()]

    lines = sorted(set(lines))

    with open(filename, 'w', encoding="utf-8") as file:
        for line in lines:
            file.write(line.replace(' ', '') + '\n')

    logger.info("URL 去重: %s (%d → %d)", filename,
                len(lines), len(set(lines)))