import socket

def write_urls_to_domains_file(domains_file):
    # 创建一个列表，用于存储输出的URL
    urls = []
    # 读取包含域名的文本文件，每行一个域名
    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f]

    # 对每个域名进行检查
    for domain in domains:
        try:
            # 解析域名的IP地址
            ip = socket.gethostbyname(domain)
            # 检查80和443端口
            for port in [80, 443]:
                # 创建一个 TCP 连接
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((ip, port))

                # 检查连接是否成功
                if result == 0:
                    # 添加带有协议的URL到列表中
                    if port == 80:
                        urls.append(f"http://{domain}")
                    elif port == 443:
                        urls.append(f"https://{domain}")
                # 关闭连接
                s.close()
        except socket.gaierror:
            print(f"无法解析域名 {domain}")
        except socket.error:
            print(f"无法连接到 {domain}")

    # 将带有协议的URL写入文件
    with open(domains_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")

    print("URLs 已写入"+ domains_file +"文件。")