import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import ipaddress
import urllib3
import oui
import macaddress
import netifaces
from tabulate import tabulate
from wcwidth import wcswidth
from collections import Counter
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import Ether, ARP, srp

def ip_to_cidr(ip):
    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(network)

def get_internal_ip_list():
    ip_list = []
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4_addresses = addresses[netifaces.AF_INET]
            for ipv4_address in ipv4_addresses:
                ip = ipv4_address['addr']
                if ip != '127.0.0.1':
                    ip_list.append(ip)
    return ip_list

def get_last_internal_ip():
    ip_list = get_internal_ip_list()
    return find_ip(ip_list)

def find_ip(ip_list):
    for ip in ip_list:
        if ip.startswith('192.168'):
            return ip
    return ip_list[-1]

def get_mac_address(ip_address):
    """
    使用 Scapy 获取指定 IP 地址的 MAC 地址
    """
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    try:
        result = srp(packet, timeout=3, verbose=0)[0]
        # 返回 MAC 地址
        return result[0][1].hwsrc
    except IndexError:
        return None

def get_mac_oui(mac):
    """
       获取MAC地址的OUI信息
       比如 68:DD:B7:75:74:D1 得到 68DDB7
       据此可以从数据库中得到设备制造商信息
    """
    try:
        # 使用macaddress库解析MAC地址
        mac_obj = macaddress.EUI48(mac)
        # 获取OUI（组织唯一标识符）
        oui = mac_obj.oui
        return str(oui).replace('-', '')
    except ValueError:
        return "无效的MAC地址"

def get_huawei(url):
    api = url + '/api/system/deviceinfo'
    api_response = requests.get(url = api, timeout=1, verify=False)
    json = api_response.json()
    return json["FriendlyName"]

def get_title(url):
    # 忽略 InsecureRequestWarning 警告
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        # 允许跟随重定向,并忽略证书验证
        response = requests.get(url, timeout=1, verify=False)
        if response.status_code == 200:
            response.encoding = response.apparent_encoding  # 设置编码为响应的推测编码
            title = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            title = title.group(1) if title else response.headers['SERVER']
            if title == 'Success':
                title = get_huawei(url)
            return title
    except requests.RequestException as e:
        return None

def get_devtype(device_str):
    device_map = {
        "摄像头": {"IPC"},
        "录像机": {"NVR"},
        "打印机": {"^EPSON"},
        "智能网关": {"米家自动化极客版"},
        "路由器": {"^TL-", "^NETGEAR", "^路由"}
    }
    for dev_type, identifiers in device_map.items():
        for identifier in identifiers:
            if identifier.startswith("^"):
                # 使用正则表达式进行匹配
                pattern = identifier[1:]  # 去掉开头的^符号
                if re.search(pattern, device_str):
                    return dev_type
            else:
                # 进行完全匹配
                if device_str == identifier or device_str.startswith(identifier):
                    return dev_type
    
    return "Unknown"

def check_port(ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)  # 设置超时
            result = s.connect_ex((ip, 80))  # 尝试连接80端口
            if result == 0:  # 端口开放
                # 透过MAC地址得到厂商信息
                mac_address=get_mac_address(ip)
                mac_oui=get_mac_oui(mac_address)
                organization=oui.get_organization(mac_oui)
                title = get_title(f'http://{ip}')
                devtype = get_devtype(title + organization)
                return ip, devtype, title, organization
    except Exception as e:
        print(f"Error checking {ip}: {e}")
    return None

def main():
    ascii_art = r"""

             _____ _____ _____                 
            |  _  |  _  /  ___|                
 _ __  _   _ \ V /| |/' \ `--.  ___ __ _ _ __  
| '_ \| | | |/ _ \|  /| |`--. \/ __/ _` | '_ \ 
| |_) | |_| | |_| \ |_/ /\__/ / (_| (_| | | | |
| .__/ \__, \_____/\___/\____/ \___\__,_|_| |_|
| |     __/ |                                  
|_|    |___/                                   

    py80Scan 局域网80端口扫描工具, 基于 npcap.com
        """
    inner_ip = ip_to_cidr(get_last_internal_ip()) # 获取内网IP cidr 比如 192.168.9.0/24
    print(ascii_art)
    ip_range = input(f"请输入IP段 (直接回车键则 {inner_ip}): ") or inner_ip
    network = ipaddress.ip_network(ip_range)
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(check_port, str(ip)): str(ip) for ip in network.hosts()}
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                results.append(result)
    
    if len(results) == 0:
        print('! 没有找到任何设备在80端口。')
        return
    # 打印表格
    print_table(results)
    len_count = len(results)

    # 打印统计信息
    device_counts = Counter(device for _, device, _, _ in results)
    device_stats = ', '.join(f"{device}{count}台" for device, count in device_counts.items())
    print(device_stats)
    print(f"一共有{len_count}台设备。")

def print_table(results):
    # 计算每列的最大宽度
    def calculate_max_width(data):
        max_widths = []
        for col in zip(*data):  # 转置数据以按列处理
            max_width = max(wcswidth(str(item)) for item in col)  # 计算每列的最大宽度
            max_widths.append(max_width)
        return max_widths

    # 计算列宽
    max_widths = calculate_max_width(results)

    # 使用 tabulate 输出表格
    table = tabulate(results, headers=["IP Address", "DevType", "Title", "Organization"], tablefmt="grid", stralign="left", numalign="center")

    # 打印表格
    print(table)

if __name__ == "__main__":
    try:
        main()
        print("按回车键退出。")
        input()
    except KeyboardInterrupt:
        print("\nExiting program...")
        exit()
