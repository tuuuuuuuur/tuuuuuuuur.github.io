import ipaddress
import json
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tqdm import tqdm


def ping_ip(ip):
    """
    """
    system = platform.system().lower()

    if system == "windows":
        command = ['ping', '-n', '1', ip]
    else:
        command = ['ping', '-c', '1', ip]

    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def scan_subnet_range(start_ip="192.168.0.0", end_ip="192.168.1.255", num_threads=300):
    """
    """
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    active_ips = []

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_ip = {executor.submit(ping_ip, str(ip)): ip for ip in range(int(start), int(end) + 1)}

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    active_ips.append(str(ip))
            except Exception as exc:
                print(f'Error pinging {ip}: {exc}')

    return active_ips


def get_address_str(ip_list):
    ret_list = []
    for add_ip in ip_list:
        ip_address = ipaddress.IPv4Address(int(add_ip))
        ret_list.append(str(ip_address))
    return ret_list


req = requests.get(url="https://tuuuuuuuur.github.io/hosts.json").text
ports_info = json.loads(req)


def check_port(ip, port, timeout=0.5):
    try:
        with socket.create_connection((ip, port), timeout):
            return True
    except (ConnectionRefusedError, OSError, socket.gaierror):
        return False


def scan_high_risk_ports(ip, ports_info):
    total_ports = sum(len(port_info) for port_info in ports_info)
    security = 0
    doc_list = []
    with tqdm(total=total_ports, desc="扫描进度", unit="端口") as pbar:
        for port_info in ports_info:
            for port_str, details in port_info.items():
                port = int(port_str)
                if check_port(ip, port):
                    security = security + 1
                    dist = [f"目标端口：{port} 类型：({details['server']}) 目标IP：{ip} 可能开放：{details['doc']}"]
                    doc_list.append(dist)
                pbar.update(1)

    return doc_list


def main():
    while True:
        user_input = input("Server-> ")
        if user_input.lower() == "q":
            exit()
        elif user_input == "h" or user_input == "H":
            print("ip_check" + "\n" +
                  "扫描网段内存活IP" + "\n" +
                  "ip_sec" + "\n" +
                  "扫描IP存在端口")
        elif user_input == "ip_check":
            start_ip = input("起始IP: ")
            end_ip = input("截止IP: ")
            num = int(input("QPS: "))
            addresses = scan_subnet_range(start_ip=start_ip, end_ip=end_ip, num_threads=num)
            formatted_addresses = get_address_str(addresses)
            print("\n".join(formatted_addresses) + "\n" + "存活：" + str(len(formatted_addresses)))
        elif user_input == "ip_sec":
            target_ip = input("目标IP: ")
            results = scan_high_risk_ports(target_ip, ports_info)
            print(str(results) + '\n' + "存在：" + str(len(results)) + "个高危!")
        elif user_input == None:
            print(f"不存在 {user_input} 指令，H 查看文档")
        elif user_input != "":
            print(f"不存在 {user_input} 指令，H 查看文档")


if __name__ == "__main__":
    main()
