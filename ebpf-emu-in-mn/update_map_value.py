'''
bpf map update script (Fast Version)
Created on Mon Sep 30 2024
author: yeli, Weibiao Tian
Optimized for performance using libbpf direct calls
'''
import argparse
import subprocess
import ctypes
import ctypes.util
import os
import sys

# === Libbpf Setup ===

# 尝试加载 libbpf 库
libbpf_path = ctypes.util.find_library('bpf')
if not libbpf_path:
    # 常见的 libbpf 位置，如果 find_library 找不到
    possible_paths = [
        '/usr/lib/x86_64-linux-gnu/libbpf.so', 
        '/usr/lib64/libbpf.so', 
        '/usr/lib/libbpf.so'
    ]
    for p in possible_paths:
        if os.path.exists(p):
            libbpf_path = p
            break

if not libbpf_path:
    print("Error: libbpf.so not found. Please install libbpf-dev or ensure libbpf.so is in your library path.")
    sys.exit(1)

try:
    libbpf = ctypes.CDLL(libbpf_path)
    
    # 定义 C 函数签名
    # int bpf_map_get_fd_by_id(__u32 id);
    libbpf.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint32]
    libbpf.bpf_map_get_fd_by_id.restype = ctypes.c_int
    
    # int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
    libbpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    libbpf.bpf_map_update_elem.restype = ctypes.c_int
    
except Exception as e:
    print(f"Error loading libbpf functions: {e}")
    sys.exit(1)

# === Helper Functions ===

def get_map_id(keyword):
    """通过 bpftool 获取 map id (只需要运行一次)"""
    try:
        # 使用 sudo 确保能看到所有 map
        cmd = ['sudo', 'bpftool', 'map', 'show']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        for line in result.stdout.splitlines():
            if keyword in line:
                # 行格式示例: "123: array  name my_map  flags 0x0"
                parts = line.split()
                map_id = parts[0][:-1]  # 移除冒号
                return int(map_id)
                
    except subprocess.CalledProcessError as e:
        print(f"Error in running bpftool: {e}")
    except Exception as e:
        print(f"Error finding map: {e}")
    return None

def update_bpf_map_fast(map_id, file_path):
    """使用 libbpf 直接更新 map，避免进程创建开销"""
    print(f"Using libbpf to update map {map_id} from {file_path}...")
    
    # 1. 获取 Map 的文件描述符 (FD)
    # 这对应于 bpf_map_get_fd_by_id 系统调用
    map_fd = libbpf.bpf_map_get_fd_by_id(map_id)
    if map_fd < 0:
        print(f"Failed to get FD for map ID {map_id}. Do you have sudo permissions?")
        return

    count = 0
    try:
        with open(file_path, 'r') as file:
            for key, line in enumerate(file):
                line = line.strip()
                if not line:
                    continue
                    
                value = int(line)
                
                # 准备 C 类型的数据
                # key 是 __u32 (4字节)
                c_key = ctypes.c_uint32(key)
                # value 是 int/__u32 (4字节) - 根据原来的 xdp_drop_packet.c 定义
                c_value = ctypes.c_uint32(value) 
                
                # 调用 libbpf 函数更新 map
                # flags = 0 (BPF_ANY)
                ret = libbpf.bpf_map_update_elem(map_fd, ctypes.byref(c_key), ctypes.byref(c_value), 0)
                
                if ret != 0:
                    err = ctypes.get_errno()
                    print(f"Failed to update key {key} with value {value}: errno {err}")
                    # 如果需要调试，可以取消下面的注释
                    # break 
                count += 1
                
        print(f"Successfully updated {count} items in map {map_id}.")
        
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except ValueError as e:
        print(f"Error parsing file content: {e}")
    except Exception as e:
        print(f"Error during fast update: {e}")
    finally:
        # 关闭文件描述符
        os.close(map_fd)

if __name__ == "__main__":
    # 检查 root 权限
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo) to access BPF maps.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Update BPF map with values from a given file (Fast Mode).')
    
    parser.add_argument('--keyword', required=True, help='The keyword to identify the BPF map.')
    parser.add_argument('--file_path', required=True, help='The file path from which to read values.')

    args = parser.parse_args()

    map_id = get_map_id(args.keyword)
    
    if map_id is not None:
        update_bpf_map_fast(map_id, args.file_path)
    else:
        print(f"Map with keyword '{args.keyword}' not found.")