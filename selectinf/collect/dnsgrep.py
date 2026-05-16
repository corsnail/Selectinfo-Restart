import requests
from bs4 import BeautifulSoup
from selectinf import get_logger

logger = get_logger("collect.dnsgrep")


def get_unique_domains(url):
    # 自动补全 scheme
    if '://' not in url:
        url = 'https://' + url
        logger.debug("DNS 查询 URL 自动补全: %s", url)

    def craw(url):
        r = requests.get(url)
        return r.text

    def parse(html):
        soup = BeautifulSoup(html, 'html.parser')
        td_tags = soup.find_all("td")
        content_list = [td.get_text(strip=True) for td in td_tags]
        return content_list

    domain_name = url.split('/')[-1]

    try:
        results = parse(craw(url))
    except requests.exceptions.ProxyError as e:
        logger.error(
            "[dnsgrep] 代理连接失败: %s。"
            "请检查系统代理设置，或临时禁用代理后重试。",
            e,
        )
        return
    except requests.exceptions.ConnectionError as e:
        logger.error("[dnsgrep] 网络连接失败: %s", e)
        return
    except Exception as e:
        logger.error("[dnsgrep] DNS HTML 解析失败: %s", e)
        return

    file_name = f"{domain_name}.txt"

    unique_domains = set()

    for result in results:
        if '.' in result:
            domain = result.strip()
            if all(ord(c) < 128 for c in domain):
                unique_domains.add(domain)

    with open(file_name, 'a', encoding='utf-8') as file:
        for domain in unique_domains:
            file.write(domain + '\n')

    logger.info("DNS 发现: %s (%d 条)", file_name, len(unique_domains))