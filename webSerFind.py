#!/usr/bin/env python3
"""
Web服务探测工具
功能：扫描IP的端口，检测HTTP/HTTPS服务，提取页面标题，保存结果
"""

import argparse
import socket
import ssl
import threading
import time
import queue
import sys
import signal
import os
from datetime import datetime
from urllib import request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
import ipaddress
from html.parser import HTMLParser

# 全局变量，用于控制程序退出
running = True

def signal_handler(sig, frame):
    """处理Ctrl+C信号"""
    global running
    print("\n[!] 接收到中断信号，正在退出...")
    running = False
    sys.exit(0)

class TitleParser(HTMLParser):
    """HTML标题解析器"""
    def __init__(self):
        super().__init__()
        self.title = ""
        self.in_title = False
        
    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
            
    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
            
    def handle_data(self, data):
        if self.in_title:
            self.title += data
            
    def get_title(self):
        """获取解析到的标题"""
        title = self.title.strip()
        return title if title else "No Title"

def check_port(ip, port, timeout=2):
    """检查端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def check_http_service(ip, port, timeout=2, use_ssl=False):
    """检查HTTP/HTTPS服务并获取标题"""
    protocol = "https" if use_ssl else "http"
    url = f"{protocol}://{ip}:{port}"
    
    try:
        # 设置请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection': 'close'
        }
        
        # 创建请求
        req = request.Request(url, headers=headers)
        
        if use_ssl:
            # 创建SSL上下文，忽略证书验证
            context = ssl._create_unverified_context()
            response = request.urlopen(req, timeout=timeout, context=context)
        else:
            response = request.urlopen(req, timeout=timeout)
        
        # 读取响应内容
        content = response.read().decode('utf-8', errors='ignore')
        
        # 解析标题
        parser = TitleParser()
        parser.feed(content)
        title = parser.get_title()
        
        return True, title, response.getcode()
    except HTTPError as e:
        # HTTP错误但仍然可以获取标题
        try:
            content = e.read().decode('utf-8', errors='ignore')
            parser = TitleParser()
            parser.feed(content)
            title = parser.get_title()
            return True, title, e.code
        except:
            return True, f"HTTP Error: {e.code}", e.code
    except (URLError, socket.timeout, ConnectionError, ssl.SSLError):
        return False, None, None
    except Exception as e:
        return False, None, None

def worker(ip, port_queue, results_queue, timeout, output_file, lock):
    """工作线程函数"""
    while running and not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break
            
        if check_port(ip, port, timeout):
            # 尝试HTTP
            http_success, http_title, http_code = check_http_service(ip, port, timeout, False)
            
            # 尝试HTTPS
            https_success, https_title, https_code = check_http_service(ip, port, timeout, True)
            
            if http_success or https_success:
                result = {
                    'ip': ip,
                    'port': port,
                    'http': http_success,
                    'https': https_success,
                    'http_title': http_title,
                    'https_title': https_title,
                    'http_code': http_code,
                    'https_code': https_code
                }
                results_queue.put(result)
                
                # 输出到控制台
                output = []
                if http_success:
                    output.append(f"HTTP:  http://{ip}:{port}")
                    output.append(f"      Title: {http_title} (Code: {http_code})")
                if https_success:
                    output.append(f"HTTPS: https://{ip}:{port}")
                    output.append(f"      Title: {https_title} (Code: {https_code})")
                
                print("\n".join(output))
                print("-" * 50)
                
                # 写入文件
                with lock:
                    with open(output_file, 'a', encoding='utf-8') as f:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"[{timestamp}]\n")
                        if http_success:
                            f.write(f"HTTP:  http://{ip}:{port}\n")
                            f.write(f"      Title: {http_title} (Code: {http_code})\n")
                        if https_success:
                            f.write(f"HTTPS: https://{ip}:{port}\n")
                            f.write(f"      Title: {https_title} (Code: {https_code})\n")
                        f.write("-" * 50 + "\n")
        
        port_queue.task_done()

def parse_ports(port_str):
    """解析端口范围字符串"""
    ports = set()
    
    # 处理逗号分隔和范围
    parts = port_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 1 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
                else:
                    print(f"[!] 无效的端口范围: {part}")
                    sys.exit(1)
            except ValueError:
                print(f"[!] 无效的端口范围格式: {part}")
                sys.exit(1)
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    print(f"[!] 端口号超出范围: {port}")
                    sys.exit(1)
            except ValueError:
                print(f"[!] 无效的端口号: {part}")
                sys.exit(1)
    
    return sorted(ports)

def validate_ip(ip_str):
    """验证IP地址"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def main():
    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(
        description="Web服务探测工具 - 扫描IP的端口，检测HTTP/HTTPS服务，提取页面标题",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s 192.168.1.1 -p 80,443,8080 -t 20 --timeout 3
  %(prog)s 192.168.1.1 -p 1-1000 -t 50
  %(prog)s 192.168.1.1 -p 1-65535 -t 100 --timeout 2
        """
    )
    
    parser.add_argument("ip", help="目标IP地址")
    parser.add_argument("-p", "--ports", default="80,443,8080,8000,8888,3000,5000,7000,9000",
                       help="要扫描的端口范围，支持逗号分隔和连字符范围（默认: 80,443,8080,8000,8888,3000,5000,7000,9000）")
    parser.add_argument("-t", "--threads", type=int, default=20,
                       help="线程数（默认: 20）")
    parser.add_argument("--timeout", type=float, default=2.0,
                       help="超时时间（秒）（默认: 2）")
    parser.add_argument("-o", "--output", default=None,
                       help="输出文件名（默认: web_scan_结果_时间戳.txt）")
    
    args = parser.parse_args()
    
    # 验证IP地址
    if not validate_ip(args.ip):
        print(f"[!] 无效的IP地址: {args.ip}")
        sys.exit(1)
    
    # 解析端口
    ports = parse_ports(args.ports)
    print(f"[*] 目标IP: {args.ip}")
    print(f"[*] 扫描端口: {len(ports)} 个")
    print(f"[*] 线程数: {args.threads}")
    print(f"[*] 超时时间: {args.timeout}秒")
    
    # 准备输出文件
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"web_scan_{args.ip}_{timestamp}.txt"
    
    # 初始化队列
    port_queue = queue.Queue()
    results_queue = queue.Queue()
    
    # 将端口添加到队列
    for port in ports:
        port_queue.put(port)
    
    # 创建锁和线程列表
    lock = threading.Lock()
    threads = []
    
    # 清空输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Web服务扫描报告\n")
        f.write(f"目标IP: {args.ip}\n")
        f.write(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"扫描端口数: {len(ports)}\n")
        f.write(f"线程数: {args.threads}\n")
        f.write(f"超时时间: {args.timeout}秒\n")
        f.write("=" * 50 + "\n\n")
    
    print(f"[*] 开始扫描... (按 Ctrl+C 停止)")
    print(f"[*] 结果将保存到: {output_file}")
    print("=" * 50)
    
    start_time = time.time()
    
    # 创建并启动工作线程
    for i in range(min(args.threads, len(ports))):
        thread = threading.Thread(
            target=worker,
            args=(args.ip, port_queue, results_queue, args.timeout, output_file, lock)
        )
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    # 等待所有端口处理完成
    try:
        port_queue.join()
    except KeyboardInterrupt:
        print("\n[!] 用户中断扫描")
        global running
        running = False
    
    # 等待所有线程完成
    for thread in threads:
        thread.join(timeout=1)
    
    # 收集结果
    results = []
    while not results_queue.empty():
        results.append(results_queue.get())
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # 生成摘要
    http_count = sum(1 for r in results if r['http'])
    https_count = sum(1 for r in results if r['https'])
    
    # 输出摘要
    print("\n" + "=" * 50)
    print("扫描完成!")
    print(f"发现HTTP服务: {http_count} 个")
    print(f"发现HTTPS服务: {https_count} 个")
    print(f"总耗时: {elapsed_time:.2f} 秒")
    print(f"结果已保存到: {output_file}")
    
    # 更新输出文件中的摘要信息
    with open(output_file, 'a', encoding='utf-8') as f:
        f.write("\n" + "=" * 50 + "\n")
        f.write("扫描摘要:\n")
        f.write(f"发现HTTP服务: {http_count} 个\n")
        f.write(f"发现HTTPS服务: {https_count} 个\n")
        f.write(f"结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总耗时: {elapsed_time:.2f} 秒\n")

if __name__ == "__main__":
    # 检查Python版本
    if sys.version_info < (3, 6):
        print("[!] 需要Python 3.6或更高版本")
        sys.exit(1)
    
    # 显示程序标题
    print("=" * 50)
    print("Web服务探测工具 v1.0")
    print("=" * 50)
    
    main()