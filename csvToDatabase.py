import csv
import pymysql

# 连接数据库
def connect_database():
    try:
        # 从配置文件读取数据库的连接信息
        with open('database.conf', 'r') as database:
            # 解析配置文件中的信息
            host, user, password, db, port = [line.split('=')[1].strip() for line in database.readlines()]
        # 使用pymysql库连接数据库
        database = pymysql.connect(
            host=host, user=user, passwd=password, database=db, port=int(port))
        print('数据库连接成功')
        return database
    except :
        # 出现异常，连接失败
        print('数据库连接失败,检查database.conf')
        exit()

# 打开CSV文件
def open_csv(filename):
    try:
        file = open(filename, 'r', encoding='utf-8')
        reader = csv.reader(file)
        return reader
    except:
        print(f'文件打开失败,文件"{filename}"可能不存在')
        exit()

# 创建数据表
def create_table(database, url):
    url = url.replace('.', '_').strip()
    cursor = database.cursor()
    # 创建表的SQL语句
    # 根据url新建一个数据表
    # 包含字段 ID(主键) 网站URL 网站信息 网站服务器  网站状态码 网站哈希值 创建时间 更新时间 是否被删 是否漏洞
    sql = f'''CREATE TABLE IF NOT EXISTS {url} (
        id INT PRIMARY KEY AUTO_INCREMENT,
        url VARCHAR(255) COMMENT '网站URL',
        info VARCHAR(255) COMMENT '网站信息',
        server VARCHAR(255) COMMENT '网站服务器',
        status INT COMMENT '访问状态码',
        hash VARCHAR(255) COMMENT '哈希',
        create_time DATETIME COMMENT '创建时间',
        update_time DATETIME COMMENT '更新时间',
        delete_flag INT  DEFAULT 0 COMMENT '删除标志 (1为被删除,0为正常)',
        vuln_flag INT  DEFAULT 0 COMMENT '漏洞标志(0为还未检查,1为没有漏洞,2为存在漏洞)',
        CVE VARCHAR(255) COMMENT '漏洞编号'
    )'''
    try:
        # 执行SQL语句创建表
        cursor.execute(sql)
    except:
        print(f'创建数据表{url}失败')
        exit()

# 插入或更新数据库记录
def insert_or_update_database(database, data, url):
    cursor = database.cursor()
    # 查询数据库中是否已存在该URL的记录
    sql = f'SELECT * FROM {url} WHERE url = %s'
    cursor.execute(sql, data[0])
    result = cursor.fetchone()
    if result:
        # 如果已存在记录，则执行更新操作
        sql = f'UPDATE {url} SET info = %s, server = %s, status = %s, hash = %s, update_time = NOW() WHERE url = %s'
        params = (data[1].strip(), data[2].strip(), data[3].strip(), data[4].strip(), data[0].strip())
    else:
        # 如果不存在记录，则执行插入操作
        sql = f'INSERT INTO {url}(url, info, server, status ,hash, create_time) VALUES (%s, %s, %s, %s, %s, NOW())'
        params = (data[0].strip(), data[1].strip(), data[2].strip(), data[3].strip(), data[4].strip())
    try:
        # 执行SQL语句插入或更新记录
        cursor.execute(sql, params)
    except pymysql.err.InterfaceError as e:
        print("写入数据库失败:", str(e))
        exit()
    database.commit()
    cursor.close()

# 关闭数据库连接
def close_database(database):
    database.close()

# 将CSV文件内容导入数据库
# 模块主入口
def csvToDatabase(URL):
    reader = open_csv(f'{URL}.csv')
    database = connect_database()
    url = URL.replace('.', '_').strip()
    create_table(database=database, url=url)
    for item in reader:
        try:
            insert_or_update_database(database, item, url)
        except:
            print("写入数据库失败")
            return False
    close_database(database)
    return True

