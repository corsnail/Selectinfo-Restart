import socket
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

def filter_wildcard_domains(file_path):
    def is_wildcard_resolvable(domain):
        try:
            wildcard_ip = socket.gethostbyname("random-subdomain-that-does-not-exist." + domain)
            target_ip = socket.gethostbyname(domain)
            return wildcard_ip == target_ip
        except socket.gaierror:
            return False

    def read_domains_from_file(file_path):
        with open(file_path, 'r') as file:
            for line in file:
                domain = line.strip()  # 去除行末尾的换行符和空格
                yield domain

    def write_domains_to_file(file_path, domains):
        with open(file_path, 'w') as file:
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

    # 使用生成器逐行处理域名列表
    domain_generator = read_domains_from_file(file_path)

    # 处理域名列表，过滤出正常解析的域名
    normal_domains = process_domains(domain_generator)

    # 将结果覆盖回原文件
    write_domains_to_file(file_path, normal_domains)

