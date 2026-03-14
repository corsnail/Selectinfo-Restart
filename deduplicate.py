def deduplicate_domains(file_name):

    with open(file_name, "r") as f:
        domains = f.read().splitlines()

    # remove spaces from each line
    domains = [domain.replace(" ", "") for domain in domains]

    unique_domains = sorted(set(domains))

    with open(file_name, "w") as f:
        for domain in unique_domains:
            f.write(domain + "\n")

    print("已将{}中的域名进行去重。".format(file_name))
def deduplicate_url(filename):
    with open(filename, 'r') as file:
        # 读取所有行并去除行首和行尾空格
        lines = [line.strip() for line in file.readlines()]

    # 去重并按字典序排序
    lines = sorted(set(lines))

    with open(filename, 'w') as file:
        # 将每行中的空格替换为空并写回文件
        for line in lines:
            file.write(line.replace(' ', '') + '\n')
    print("已将{}中的域名进行去重。".format(filename))