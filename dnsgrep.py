import requests
from bs4 import BeautifulSoup
def get_unique_domains(url):
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
    except Exception as e:
        print(f"Error occurred while parsing the HTML content: {e}")
        return

    file_name = f"{domain_name}.txt"  # 构建文件名

    unique_domains = set()  # 存储唯一的域名

    for result in results:
        if '.' in result:  # 判断是否为域名
            domain = result.strip()
            if all(ord(c) < 128 for c in domain):  # 检查是否只包含 ASCII 字符
                unique_domains.add(domain)

    with open(file_name, 'a', encoding='utf-8') as file:
        for domain in unique_domains:
            file.write(domain + '\n')