#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import argparse


def hide_data(input_image_path, data_file_path, output_image_path):
    """
    将数据文件隐藏到BMP图像中
    
    Args:
        input_image_path: 输入的BMP图像路径
        data_file_path: 需要隐藏的数据文件路径
        output_image_path: 输出的包含隐藏数据的BMP图像路径
    """
    # 读取原始BMP图像
    with open(input_image_path, 'rb') as f:
        bmp_header = f.read(54)  # BMP文件头通常为54字节
        
        # 解析BMP文件头以获取图像信息
        size = struct.unpack('<I', bmp_header[2:6])[0]
        offset = struct.unpack('<I', bmp_header[10:14])[0]
        width = struct.unpack('<I', bmp_header[18:22])[0]
        height = struct.unpack('<I', bmp_header[22:26])[0]
        
        # 读取剩余文件头(如果有)
        f.seek(0)
        header = f.read(offset)
        
        # 读取像素数据
        pixel_data = bytearray(f.read())
    
    # 读取要隐藏的数据
    with open(data_file_path, 'rb') as f:
        data = f.read()
    
    # 检查图像容量是否足够
    max_bytes = len(pixel_data) // 8  # 每8个字节可以隐藏1个字节
    data_size = len(data)
    
    if data_size + 8 > max_bytes:  # 加8是因为我们需要存储数据大小
        print(f"错误: 图像容量不足，最多可隐藏 {max_bytes - 8} 字节，但需要隐藏 {data_size} 字节")
        return False
    
    # 首先在像素数据中隐藏数据大小（4字节）
    size_bytes = struct.pack('<I', data_size)
    for i in range(4):
        size_byte = size_bytes[i]
        for bit_idx in range(8):
            bit = (size_byte >> bit_idx) & 1
            # 设置像素字节的最低有效位
            pixel_data[i * 8 + bit_idx] = (pixel_data[i * 8 + bit_idx] & 0xFE) | bit
    
    # 在像素数据中隐藏实际数据
    for i in range(data_size):
        data_byte = data[i]
        for bit_idx in range(8):
            bit = (data_byte >> bit_idx) & 1
            # 设置像素字节的最低有效位
            pixel_data[(i + 4) * 8 + bit_idx] = (pixel_data[(i + 4) * 8 + bit_idx] & 0xFE) | bit
    
    # 写入隐藏了数据的BMP文件
    with open(output_image_path, 'wb') as f:
        f.write(header)
        f.write(pixel_data)
    
    print(f"成功隐藏 {data_size} 字节数据到图像中")
    return True


def extract_data(stego_image_path, output_data_path):
    """
    从BMP图像中提取隐藏的数据
    
    Args:
        stego_image_path: 包含隐藏数据的BMP图像路径
        output_data_path: 提取数据保存的路径
    """
    # 读取包含隐藏数据的BMP图像
    with open(stego_image_path, 'rb') as f:
        bmp_header = f.read(54)  # BMP文件头通常为54字节
        
        # 解析BMP文件头
        offset = struct.unpack('<I', bmp_header[10:14])[0]
        
        # 定位到像素数据
        f.seek(offset)
        pixel_data = f.read()
    
    # 首先提取数据大小（4字节）
    size_bytes = bytearray(4)
    for i in range(4):
        byte_value = 0
        for bit_idx in range(8):
            # 从像素的最低有效位提取位
            bit = pixel_data[i * 8 + bit_idx] & 1
            byte_value |= (bit << bit_idx)
        size_bytes[i] = byte_value
    
    data_size = struct.unpack('<I', size_bytes)[0]
    
    # 提取实际数据
    extracted_data = bytearray(data_size)
    for i in range(data_size):
        byte_value = 0
        for bit_idx in range(8):
            # 从像素的最低有效位提取位
            bit = pixel_data[(i + 4) * 8 + bit_idx] & 1
            byte_value |= (bit << bit_idx)
        extracted_data[i] = byte_value
    
    # 保存提取的数据
    with open(output_data_path, 'wb') as f:
        f.write(extracted_data)
    
    print(f"成功从图像中提取 {data_size} 字节数据")
    return True


def analyze_capacity(image_path):
    """
    分析BMP图像的最大隐藏容量
    
    Args:
        image_path: BMP图像路径
    """
    with open(image_path, 'rb') as f:
        bmp_header = f.read(54)
        
        # 解析BMP文件头
        size = struct.unpack('<I', bmp_header[2:6])[0]
        offset = struct.unpack('<I', bmp_header[10:14])[0]
        width = struct.unpack('<I', bmp_header[18:22])[0]
        height = struct.unpack('<I', bmp_header[22:26])[0]
        bit_depth = struct.unpack('<H', bmp_header[28:30])[0]
        
        # 读取剩余文件头(如果有)
        f.seek(offset)
        pixel_data_size = os.path.getsize(image_path) - offset
    
    max_bytes = pixel_data_size // 8  # 每8个像素字节可以隐藏1个字节
    usable_bytes = max_bytes - 8  # 减去用于存储大小的字节
    
    print(f"BMP图像信息:")
    print(f"  宽度: {width}像素")
    print(f"  高度: {height}像素")
    print(f"  色深: {bit_depth}位")
    print(f"  像素数据大小: {pixel_data_size}字节")
    print(f"  最大可隐藏数据: {usable_bytes}字节 ({usable_bytes/1024:.2f}KB)")
    
    return usable_bytes


def main():
    parser = argparse.ArgumentParser(description='BMP图像隐写工具')
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # 隐藏命令
    hide_parser = subparsers.add_parser('hide', help='隐藏数据到BMP图像')
    hide_parser.add_argument('-i', '--input', required=True, help='输入的BMP图像')
    hide_parser.add_argument('-d', '--data', required=True, help='需要隐藏的数据文件')
    hide_parser.add_argument('-o', '--output', required=True, help='输出的BMP图像')
    
    # 提取命令
    extract_parser = subparsers.add_parser('extract', help='从BMP图像中提取数据')
    extract_parser.add_argument('-i', '--input', required=True, help='包含隐藏数据的BMP图像')
    extract_parser.add_argument('-o', '--output', required=True, help='提取数据的输出文件')
    
    # 分析命令
    analyze_parser = subparsers.add_parser('analyze', help='分析BMP图像的隐藏容量')
    analyze_parser.add_argument('-i', '--input', required=True, help='要分析的BMP图像')
    
    args = parser.parse_args()
    
    if args.command == 'hide':
        if not os.path.exists(args.input):
            print(f"错误: 输入图像 '{args.input}' 不存在")
            return
        if not os.path.exists(args.data):
            print(f"错误: 数据文件 '{args.data}' 不存在")
            return
        hide_data(args.input, args.data, args.output)
    
    elif args.command == 'extract':
        if not os.path.exists(args.input):
            print(f"错误: 输入图像 '{args.input}' 不存在")
            return
        extract_data(args.input, args.output)
    
    elif args.command == 'analyze':
        if not os.path.exists(args.input):
            print(f"错误: 输入图像 '{args.input}' 不存在")
            return
        analyze_capacity(args.input)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()