import re
import csv
import subprocess
import sys
import os

url = sys.argv[1]

def extract_domain_ksubdomain():
    try:
        with open("ksubdomain.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print("ksubdomain.txt 文件不存在，跳过该步骤。")
        return

    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", content)

    output_file = url + ".txt"  # 将文件名设为 url.txt

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")
    print("ksubdomain.txt的内容已追加到{}中。".format(output_file))

    # 删除源文件
    os.remove("ksubdomain.txt")
    print("已删除ksubdomain.txt。")

def extract_domain_massdns():
    try:
        with open("massdns.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print("massdns.txt 文件不存在，跳过该步骤。")
        return

    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", content)

    output_file = url + ".txt"

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")
    print("massdns.txt的内容已追加到{}中。".format(output_file))

    # 删除源文件
    os.remove("massdns.txt")
    print("已删除massdns.txt。")

def extract_domain_amass():
    try:
        with open("amass.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print("amass.txt 文件不存在，跳过该步骤。")
        return

    domains = content.split("\n")

    output_file = url + ".txt"

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")

    print("amass.txt的内容已追加到{}中。".format(output_file))

    # 删除源文件
    os.remove("amass.txt")
    print("已删除amass.txt。")

def extract_domain_subfinder():
    try:
        with open("subfinder.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print("subfinder.txt 文件不存在，跳过该步骤。")
        return

    domains = content.split("\n")

    output_file = url + ".txt"

    with open(output_file, "a", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")

    print("subfinder.txt的内容已追加到{}中。".format(output_file))

    # 删除源文件
    os.remove("subfinder.txt")
    print("已删除subfinder.txt。")

def extract_domain_OneForAll(url):
    csv_file = r"OneForAll\results\{}.csv".format(url)
    txt_file = url + ".txt"

    domain_list = []

    try:
        with open(csv_file, "r", encoding="gbk") as file:
            reader = csv.reader(file)
            for row in reader:
                url = row[0]
                domain = re.findall(r"https?://([^\s/$.?#].[^\s]*)", url)
                if domain:
                    domain_list.append(domain[0])
    except FileNotFoundError:
        print("OneForAll CSV 文件不存在，跳过该步骤。")
        return

    with open(txt_file, "a") as file:
        for domain in domain_list:
            file.write(domain + "\n")
            
    print("{}文件的内容已追加到{}中。".format(csv_file, txt_file))

    # 删除源文件
    os.remove(csv_file)
    print("已删除{}。".format(csv_file))

try:
    extract_domain_ksubdomain()
    extract_domain_massdns()
    extract_domain_amass()
    extract_domain_subfinder()
    extract_domain_OneForAll(url)
except Exception as e:
    print("出现错误:", e)

output_file = url + ".txt"
print("域名已提取并保存到{}中。".format(output_file))