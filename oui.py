import sqlite3
import requests
import re

def get_organization(oui):
    # 连接到SQLite数据库
    conn = sqlite3.connect('oui_database.db')
    c = conn.cursor()
    """
    根据给定的oui查询organization
    """
    c.execute("SELECT organization FROM oui WHERE oui = ?", (oui,))
    result = c.fetchone()
    # 关闭数据库连接
    conn.close()
    if result:
        return result[0]
    else:
        return ""

# 解析OUI文本数据
def parse_oui_data(oui_text):
    oui_entries = []
    lines = oui_text.strip().split('\n')
    
    entry = {}
    for line in lines:
        # 匹配OUI和组织名称
        match = re.match(r'([0-9A-Fa-f-]+)\s+\(hex\)\s+(.*)', line)
        if match:
            if entry:
                oui_entries.append(entry)  # 保存之前的条目
            entry = {
                'oui': match.group(1).replace('-', '').upper(),  # 去掉'-'并转为大写
                'organization': match.group(2).strip(),
            }
    
    if entry:
        oui_entries.append(entry)  # 保存最后的条目
    
    return oui_entries

# 创建SQLite数据库并插入或更新数据
def create_db_and_upsert_data(oui_entries):
    # 连接到SQLite数据库（如果不存在则创建）
    conn = sqlite3.connect('oui_database.db')
    cursor = conn.cursor()
    
    # 创建表，将OUI作为主键
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS oui (
            oui TEXT PRIMARY KEY,
            organization TEXT
        )
    ''')
    
    # 插入或更新数据
    for entry in oui_entries:
        cursor.execute('''
            INSERT INTO oui (oui, organization)
            VALUES (?, ?)
            ON CONFLICT(oui) DO UPDATE SET
                organization = excluded.organization
        ''', (entry['oui'], entry['organization']))
    
    # 提交并关闭连接
    conn.commit()
    conn.close()


def init():
    url = 'https://standards-oui.ieee.org/oui/oui.txt'
    # 发送GET请求
    response = requests.get(url)

    # 检查请求是否成功
    response.raise_for_status()  # 如果请求失败，会抛出异常

    # 获取文本内容
    oui_text = response.text
    # 解析数据并插入或更新数据库
    oui_entries = parse_oui_data(oui_text)
    create_db_and_upsert_data(oui_entries)

    print("数据已成功插入或更新SQLite数据库。")


if __name__ == "__main__":
    # 直接运行会初始化数据库
    init()