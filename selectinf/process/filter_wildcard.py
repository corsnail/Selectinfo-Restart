import socket
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from selectinf import get_logger

logger = get_logger("process.filter_wildcard")


def filter_wildcard_domains(file_path):
    if not os.path.exists(file_path):
        logger.warning("[泛解析过滤] 文件不存在，跳过: %s", file_path)
        return

    def is_wildcard_resolvable(domain):
        try:
            wildcard_ip = socket.gethostbyname("random-subdomain-that-does-not-exist." + domain)
            target_ip = socket.gethostbyname(domain)
            return wildcard_ip == target_ip
        except socket.gaierror:
            return False

    def read_domains_from_file(file_path):
        with open(file_path, 'r', encoding="utf-8") as file:
            for line in file:
                domain = line.strip()
                if domain:
                    yield domain

    def write_domains_to_file(file_path, domains):
        with open(file_path, 'w', encoding="utf-8") as file:
            for domain in domains:
                file.write(domain + '\n')

    def process_domains(domain_list):
        normal_domains = []
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(is_wildcard_resolvable, domain): domain for domain in domain_list}
            wait(futures, return_when=ALL_COMPLETED)
            for future in futures:
                domain = futures[future]
                try:
                    if not future.result():
                        normal_domains.append(domain)
                except socket.gaierror:
                    continue
        return normal_domains

    domain_generator = read_domains_from_file(file_path)
    normal_domains = process_domains(domain_generator)
    removed = len(list(read_domains_from_file(file_path))) - len(normal_domains)

    write_domains_to_file(file_path, normal_domains)
    logger.info("泛解析过滤: %s (过滤 %d 条)", file_path, removed)

