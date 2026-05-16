import requests
import json
import urllib3
import pandas as pd
import csv
import os
from selectinf import get_logger

logger = get_logger("output.arl_exporter")

apikey = ""
arl_url = "https://:5003"
headers = {
    'Content-type': 'application/json',
    'Token': apikey,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36"
}


def add(name):
    file_path = 'domain_'+name+'.txt'
    if not os.path.exists(file_path):
        logger.warning("[ARL add] 文件不存在: %s", file_path)
        return
    with open(file_path, 'r', encoding="utf-8") as file:
        domains = file.read().splitlines()

    for domain in domains:
        data = {
            "name": name,
            "task_tag": "task",
            "target": domain,
            "policy_id": "",
            "result_set_id": ""
        }
        jsondata = json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        ceshi = requests.post(f"{arl_url}/api/task/policy/", headers=headers, data=jsondata, verify=False)
        good = ceshi.text
        res = json.loads(good.encode('latin-1').decode('unicode_escape'))
        if res['message'] == 'success':
            logger.info("ARL 任务下发成功: %s", domain)
        else:
            logger.error("ARL 任务下发失败: %s", domain)



def task_id_search(name):
    file_path = 'domain_'+name+'.txt'
    if not os.path.exists(file_path):
        logger.warning("[ARL task_id_search] 文件不存在: %s", file_path)
        return []
    damains = []
    task_id = []
    task_id_list = []
    url = f"{arl_url}/api/task/?target="
    with open(file_path, 'r', encoding="utf-8") as file:
        domains = file.read().splitlines()
    for domain in domains:
        task_id_list = url + domain
        response = requests.get(task_id_list, headers=headers, verify=False)
        if response.status_code == 200:
            response_data = response.json()
            if 'items' in response_data:
                task_items = response_data['items']
                for item in task_items:
                    if '_id' in item:
                        task_id.append(item['_id'])
    return task_id
                

                
# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def send_get_requests(task_id):
    base_url = f"{arl_url}/api/export/"
    for id in task_id:
        url = f"{base_url}{id}"
        try:
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == 200:
                with open(f"output/xlsx/{id}.xlsx", "wb") as file:
                    file.write(response.content)
                logger.info("ARL 导出成功: %s", id)
            else:
                logger.warning("ARL 导出失败 (HTTP %d): %s", response.status_code, id)
        except requests.exceptions.RequestException as e:
            logger.error("ARL 请求失败: %s", e)




def xlsx_to_csv(task_id):
    for id in task_id:
        xlsx_path = f'output/xlsx/{id}.xlsx'
        if not os.path.exists(xlsx_path):
            logger.warning("[xlsx_to_csv] 文件不存在: %s", xlsx_path)
            continue
        data = pd.read_excel(xlsx_path)
        data.to_csv('output_file.csv', mode='a', index=False)
    logger.debug("xlsx → csv 转换完成 (%d 个文件)", len(task_id))



def remove_from_csv(input_file, output_file):
    columns_to_keep = ['site', 'title', '指纹', '状态码', 'favicon hash']

    with open(input_file, newline='', encoding='utf-8') as infile, open(output_file, 'a', newline='', encoding='utf-8') as outfile:
        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=columns_to_keep)
        writer.writeheader()

        for row in reader:
            cleaned_row = {column: row[column].replace('\r', '').replace('\n', '') for column in columns_to_keep}
            writer.writerow(cleaned_row)

    with open(output_file, "r", newline="", encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        lines = [line for line in reader if line != ['site', 'title', '指纹', '状态码', 'favicon hash']]

    with open(output_file, "w", newline="", encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(lines)
    os.remove("output_file.csv")
    for filename in os.listdir("output/xlsx/"):
            file_path = os.path.join("output/xlsx/", filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)
    logger.info("CSV 已清理并保存到 %s", output_file)
