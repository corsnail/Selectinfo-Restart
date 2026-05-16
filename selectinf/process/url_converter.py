import os
import socket
from selectinf import get_logger

logger = get_logger("process.url_converter")


def write_urls_to_domains_file(domains_file):
    if not os.path.exists(domains_file):
        logger.warning("[URL转换] 文件不存在，跳过: %s", domains_file)
        return
    urls = []
    with open(domains_file, 'r', encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            for port in [80, 443]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((ip, port))

                if result == 0:
                    if port == 80:
                        urls.append(f"http://{domain}")
                    elif port == 443:
                        urls.append(f"https://{domain}")
                s.close()
        except socket.gaierror:
            logger.debug("无法解析域名: %s", domain)
        except socket.error:
            logger.debug("无法连接到: %s", domain)

    with open(domains_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")

    logger.info("域名转URL: %s (%d → %d)", domains_file,
                len(domains), len(urls))