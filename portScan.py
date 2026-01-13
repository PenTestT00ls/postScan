#!/usr/bin/env python3
"""
端口扫描脚本
用法: portscan.py <目标IP> [-p 端口范围] [-t 线程数] [-T 超时时间]
示例: portscan.py 192.168.1.1 -p 1-1000 -t 100 -T 1.0
"""

import socket
import sys
import threading
import argparse
import signal
import time
from datetime import datetime

# 全局变量，用于控制扫描过程
scanning = True
open_ports = []
lock = threading.Lock()

def signal_handler(sig, frame):
    """处理Ctrl+C信号，优雅地停止扫描"""
    global scanning
    print("\n[!] 接收到中断信号，停止扫描...")
    scanning = False
    # 显示当前已发现的开放端口
    if open_ports:
        print(f"[*] 已发现的开放端口: {sorted(open_ports)}")
    sys.exit(0)

def parse_port_range(port_range):
    """解析端口范围字符串，如 '1-100' 或 '80,443,8080'"""
    ports = set()
    
    # 处理逗号分隔的端口
    if ',' in port_range:
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
    # 处理连字符范围的端口
    elif '-' in port_range:
        start, end = map(int, port_range.split('-'))
        ports.update(range(start, end + 1))
    # 单个端口
    else:
        ports.add(int(port_range))
    
    return sorted(ports)

def scan_port(target, port, timeout=1.0):
    """扫描单个TCP端口"""
    global scanning, open_ports
    
    if not scanning:
        return
    
    try:
        # 创建socket连接
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:  # 端口开放
                try:
                    # 尝试获取服务名称
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "unknown"
                
                with lock:
                    open_ports.append(port)
                    print(f"[+] 端口 {port}/tcp 开放 - 服务: {service}")
    
    except socket.timeout:
        pass  # 超时是正常的，继续扫描其他端口
    except Exception as e:
        if scanning:  # 只在扫描过程中显示错误
            print(f"[-] 扫描端口 {port} 时出错: {e}")

def worker(target, ports, timeout, results):
    """工作线程函数"""
    global scanning
    
    for port in ports:
        if not scanning:
            break
        scan_port(target, port, timeout)

def main():
    # 注册信号处理器，支持Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(
        description="Python端口扫描器",
        epilog="示例: portscan.py 192.168.1.1 -p 1-1000 -t 100 -T 1.0"
    )
    
    parser.add_argument("target", help="目标IP地址或域名")
    parser.add_argument("-p", "--ports", default="1-1000", 
                       help="端口范围 (如: 1-1000, 80,443,8080) [默认: 1-1000]")
    parser.add_argument("-t", "--threads", type=int, default=100,
                       help="线程数 [默认: 100]")
    parser.add_argument("-T", "--timeout", type=float, default=1.0,
                       help="超时时间(秒) [默认: 1.0]")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="详细模式")
    
    args = parser.parse_args()
    
    # 解析目标地址
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] 无法解析目标: {args.target}")
        sys.exit(1)
    
    # 解析端口范围
    try:
        ports_to_scan = parse_port_range(args.ports)
    except ValueError:
        print("[-] 无效的端口范围格式")
        print("[*] 正确格式示例: 1-1000 或 80,443,8080 或 22-25,80,443")
        sys.exit(1)
    
    # 验证端口范围
    if not ports_to_scan:
        print("[-] 没有有效的端口需要扫描")
        sys.exit(1)
    
    # 显示扫描信息
    print("-" * 50)
    print(f"[*] 开始扫描: {args.target} ({target_ip})")
    print(f"[*] 端口范围: {args.ports} ({len(ports_to_scan)} 个端口)")
    print(f"[*] 线程数: {args.threads}")
    print(f"[*] 超时时间: {args.timeout}秒")
    print(f"[*] 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)
    print("[*] 按 Ctrl+C 停止扫描")
    print("-" * 50)
    
    start_time = time.time()
    
    # 准备线程池
    threads = []
    results = []
    
    # 将端口列表分成多个块，每个线程处理一个块
    chunk_size = max(1, len(ports_to_scan) // args.threads)
    port_chunks = [ports_to_scan[i:i + chunk_size] 
                  for i in range(0, len(ports_to_scan), chunk_size)]
    
    # 创建并启动线程
    for chunk in port_chunks:
        thread = threading.Thread(target=worker, 
                                args=(target_ip, chunk, args.timeout, results))
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    # 等待所有线程完成或收到中断信号
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        signal_handler(None, None)
    
    # 计算扫描时间
    scan_duration = time.time() - start_time
    
    # 显示最终结果
    print("\n" + "-" * 50)
    print("[*] 扫描完成!")
    print(f"[*] 扫描耗时: {scan_duration:.2f} 秒")
    print(f"[*] 扫描速率: {len(ports_to_scan) / scan_duration:.2f} 端口/秒")
    
    if open_ports:
        print(f"[+] 发现的开放端口 ({len(open_ports)} 个):")
        for port in sorted(open_ports):
            try:
                service = socket.getservbyport(port, 'tcp')
                print(f"    {port}/tcp - {service}")
            except:
                print(f"    {port}/tcp - unknown")
    else:
        print("[-] 未发现开放端口")
    
    print("-" * 50)

if __name__ == "__main__":
    main()