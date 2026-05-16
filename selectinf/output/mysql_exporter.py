import csv
import pymysql
import sys
from selectinf import get_logger

logger = get_logger("output.mysql_exporter")


def connect_database():
    try:
        # 从配置文件读取数据库的连接信息
        with open("config/database.conf", "r") as database:
            host, user, password, db, port = [line.split("=")[1].strip() for line in database.readlines()]
        database = pymysql.connect(
            host=host, user=user, passwd=password, database=db, port=int(port))
        logger.info("数据库连接成功")
        return database
    except Exception as e:
        logger.critical("数据库连接失败: %s", e)
        sys.exit(1)


def open_csv(filename):
    try:
        file = open(filename, "r", encoding="utf-8")
        reader = csv.reader(file)
        return reader
    except Exception as e:
        logger.critical("文件打开失败: %s", e)
        sys.exit(1)


def create_table(database, url):
    url = url.replace(".", "_").strip()
    cursor = database.cursor()
    sql = f"""CREATE TABLE IF NOT EXISTS {url} (
        id INT PRIMARY KEY AUTO_INCREMENT,
        url VARCHAR(255) COMMENT "网站URL",
        info VARCHAR(255) COMMENT "网站信息",
        server VARCHAR(255) COMMENT "网站服务器",
        status INT COMMENT "访问状态码",
        hash VARCHAR(255) COMMENT "哈希",
        create_time DATETIME COMMENT "创建时间",
        update_time DATETIME COMMENT "更新时间",
        delete_flag INT  DEFAULT 0 COMMENT "删除标志 (1为被删除,0为正常)",
        vuln_flag INT  DEFAULT 0 COMMENT "漏洞标志(0为还未检查,1为没有漏洞,2为存在漏洞)",
        CVE VARCHAR(255) COMMENT "漏洞编号"
    )"""
    try:
        cursor.execute(sql)
        logger.debug("数据表 %s 就绪", url)
    except Exception as e:
        logger.critical("创建数据表 %s 失败: %s", url, e)
        sys.exit(1)


def insert_or_update_database(database, data, url):
    cursor = database.cursor()
    sql = f"SELECT * FROM {url} WHERE url = %s"
    cursor.execute(sql, data[0])
    result = cursor.fetchone()
    if result:
        sql = f"UPDATE {url} SET info = %s, server = %s, status = %s, hash = %s, update_time = NOW() WHERE url = %s"
        params = (data[1].strip(), data[2].strip(), data[3].strip(), data[4].strip(), data[0].strip())
    else:
        sql = f"INSERT INTO {url}(url, info, server, status ,hash, create_time) VALUES (%s, %s, %s, %s, %s, NOW())"
        params = (data[0].strip(), data[1].strip(), data[2].strip(), data[3].strip(), data[4].strip())
    try:
        cursor.execute(sql, params)
    except pymysql.err.InterfaceError as e:
        logger.error("写入数据库失败: %s", e)
        sys.exit(1)
    database.commit()
    cursor.close()


def close_database(database):
    database.close()


def csvToDatabase(URL):
    reader = open_csv(f"{URL}.csv")
    database = connect_database()
    url = URL.replace(".", "_").strip()
    create_table(database=database, url=url)
    count = 0
    for item in reader:
        try:
            insert_or_update_database(database, item, url)
            count += 1
        except Exception as e:
            logger.error("写入数据库失败 (第 %d 条): %s", count + 1, e)
    close_database(database)
    logger.info("数据库导入完成: %s (%d 条)", url, count)
    return True
