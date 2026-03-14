# -*- coding: utf-8 -*-
import threading
import subprocess
import os
from deduplicate import *
from GetUrl import *
from filterWildcardDomains import *
from dnsgrep import *
from arl_output import *
import csvToDatabase 


def oneforall_scan(url):
    command = f"python OneForAll/oneforall.py --target {url} run"
    os.system(command)


def massdns_scan(url):
    command = r"python massdns\scripts\subbrute.py massdns\lists\names.txt {} | massdns\bin\massdns -r massdns\lists\resolvers.txt -t A -o S -w massdns.txt".format(
        url)
    os.system(command)


def subfinder_scan(url):
    command = r"subfinder\subfinder.exe -d {} -o subfinder.txt -silent".format(
        url)
    os.system(command)


def amass_scan(url):
    command = r"amass\amass.exe enum -v -src -ip -brute -d {} -timeout 20 -active -o amass.txt".format(
        url)
    os.system(command)


def ksubdomain_scan(url):
    command = r"ksubdomain\ksubdomain.exe -d {} -b 20M -o ksubdomain.txt".format(
        url)
    os.system(command)


def scan_thread1(url):
    amass_scan(url)
    oneforall_scan(url)


def scan_thread2(url):
    massdns_scan(url)
    ksubdomain_scan(url)


def jsfinder(url):
    command = r"python jsfinder\JSFinder.py -u {} -ou url.txt -os subdomain.txt".format(
        url)
    os.system(command)


# 主函数
if __name__ == "__main__":
    url = input("请输入URL: ")

    subfinder_scan(url)
    # 创建线程列表
    threads = []
    # 创建并启动线程
    t1 = threading.Thread(target=scan_thread1, args=(url,))
    threads.append(t1)
    t1.start()

    t2 = threading.Thread(target=scan_thread2, args=(url,))
    threads.append(t2)
    t2.start()

    # 等待所有线程结束
    for thread in threads:
        thread.join()

    subprocess.call(["python", "extract_domains.py", url])
    # 域名收集

    get_unique_domains(url)
    # dns发现源

    deduplicate_domains(url+".txt")
    # 域名去重

    # for i in range(10):
    #     filter_wildcard_domains(url+'.txt')
    # print("泛解析域名去除")
    # 去除泛解析域名

    with open(url + ".txt", 'r') as f:
        content = f.read()

    with open("domain_" + url + ".txt", 'w') as f:
        f.write(content)
    # 域名存储

    write_urls_to_domains_file(url+".txt")
    # 域名转url
    visited_urls = set()
    # 创建一个空集合来记录已经访问过的 URL
    last_size = -1
    while (True):
        size = os.path.getsize(url+".txt")
        if size == last_size:
            break
        # 如果文件大小没有发生变化，则退出循环

        last_size = size
        with open(url+".txt", "r") as f:
            for line in f:
                urls = line.strip()
                if urls not in visited_urls:
                    jsfinder(urls)
                    visited_urls.add(url)
                    # 将这个 URL 添加到集合中
                    deduplicate_domains("subdomain.txt")
                    deduplicate_url(f"{url}.txt")
        # 去重
        with open(url+".txt", "a") as f:
            with open(f"{url}.txt", "r") as f2:
                for line in f2:
                    f.write(line)
        os.remove(f"{url}.txt")
        # 添加新的url

        with open("subdomain.txt", 'r') as f:
            content = f.read()

        with open("domain_" + url + ".txt", 'a') as f:
            f.write(content)
        # 添加新的域名

        write_urls_to_domains_file("subdomain.txt")
        with open(url+".txt", "a") as f:
            with open("subdomain.txt", "r") as f2:
                for line in f2:
                    f.write(line)
        os.remove("subdomain.txt")
        # 把域名转url添加
        deduplicate_domains("domain_"+url+".txt")
        deduplicate_url(url+".txt")
        print(visited_urls)
    # jsfinder遍历
    add(url)
    send_get_requests((task_id_search(f"{url}")))
    xlsx_to_csv(task_id_search(f"{url}"))
    remove_from_csv("output_file.csv", f"{url}.csv")
    #数据进入数据库
    csvToDatabase.csvToDatabase(url)
    quit=input("按任意键退出")
    if quit:
        exit()

