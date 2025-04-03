#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import argparse
import hashlib
import random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


def derive_key(password, salt):
    """
    从密码派生加密密钥
    
    Args:
        password: 用户提供的密码
        salt: 随机盐值
    
    Returns:
        32字节的密钥
    """
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key


def encrypt_data(data, password):
    """
    使用AES加密数据
    
    Args:
        data: 要加密的数据
        password: 用于派生密钥的密码
    
    Returns:
        加密后的数据，包括IV和salt
    """
    try:
        # 使用固定的16字节salt和iv
        salt = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10])
        iv = bytes([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20])
        
        print(f"[加密] 数据长度: {len(data)} 字节")
        print(f"[加密] 使用密码: {password}")
        
        # 从密码生成密钥
        key = hashlib.sha256(password.encode('utf-8')).digest()
        print(f"[加密] 生成的密钥: {key.hex()}")
        
        # 创建加密器并加密
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        final_data = salt + iv + encrypted_data
        print(f"[加密] 最终数据长度: {len(final_data)} 字节")
        print(f"[加密] Salt: {salt.hex()}")
        print(f"[加密] IV: {iv.hex()}")
        
        return final_data
    except Exception as e:
        print(f"[加密错误] {str(e)}")
        raise


def decrypt_data(encrypted_data, password):
    """
    使用AES解密数据
    
    Args:
        encrypted_data: 加密的数据
        password: 用于派生密钥的密码
    
    Returns:
        解密后的数据
    """
    try:
        print(f"[解密] 接收数据长度: {len(encrypted_data)} 字节")
        print(f"[解密] 使用密码: {password}")
        
        # 提取salt和iv
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        actual_encrypted_data = encrypted_data[32:]
        
        print(f"[解密] Salt: {salt.hex()}")
        print(f"[解密] IV: {iv.hex()}")
        print(f"[解密] 加密数据长度: {len(actual_encrypted_data)} 字节")
        
        # 从密码生成密钥
        key = hashlib.sha256(password.encode('utf-8')).digest()
        print(f"[解密] 生成的密钥: {key.hex()}")
        
        # 创建解密器
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # 解密数据
        decrypted_padded = cipher.decrypt(actual_encrypted_data)
        print(f"[解密] 解密后数据长度(含填充): {len(decrypted_padded)} 字节")
        
        # 移除填充
        try:
            result = unpad(decrypted_padded, AES.block_size)
            print(f"[解密] 成功: 最终数据长度: {len(result)} 字节")
            return result
        except ValueError as padding_error:
            print(f"[解密] 填充错误: {str(padding_error)}")
            print("错误: 密码不正确或数据已损坏")
            return None
            
    except Exception as e:
        print(f"[解密] 发生错误: {str(e)}")
        return None


def generate_indices(seed, max_index, count):
    """
    生成用于分散数据的伪随机索引
    
    Args:
        seed: 随机种子
        max_index: 最大索引值
        count: 需要的索引数量
    
    Returns:
        索引列表
    """
    random.seed(seed)
    indices = []
    used_indices = set()
    
    while len(indices) < count:
        idx = random.randint(0, max_index - 1)
        if idx not in used_indices:
            indices.append(idx)
            used_indices.add(idx)
    
    return indices


def hide_data(input_image_path, data_file_path, output_image_path, password=None):
    """
    将数据文件隐藏到BMP图像中，可选使用密码加密
    
    Args:
        input_image_path: 输入的BMP图像路径
        data_file_path: 需要隐藏的数据文件路径
        output_image_path: 输出的包含隐藏数据的BMP图像路径
        password: 可选的加密密码
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
    
    print(f"[隐藏] 原始数据大小: {len(data)} 字节")
    
    # 如果提供了密码，则加密数据
    if password:
        data = encrypt_data(data, password)
        print(f"[隐藏] 加密后数据大小: {len(data)} 字节")
    
    data_size = len(data)
    
    # 检查图像容量是否足够
    # 使用像素的最低位，每8个字节可以隐藏1个字节
    max_bytes = len(pixel_data) // 8  
    
    if data_size + 8 > max_bytes:  # 加8是因为我们需要存储数据大小和加密标志
        print(f"错误: 图像容量不足，最多可隐藏 {max_bytes - 8} 字节，但需要隐藏 {data_size} 字节")
        return False
    
    # 计算种子值(使用图像的宽高)
    seed = width * height
    if password:
        # 如果有密码，将密码哈希添加到种子
        seed += int(hashlib.md5(password.encode()).hexdigest(), 16) % 10000000
    
    # 使用种子生成数据分布的索引
    indices = generate_indices(seed, len(pixel_data) - data_size * 8, data_size * 8 + 32)
    
    # 首先在像素数据中隐藏加密标志和数据大小（4字节）
    flag_and_size = bytearray(4)
    flag_and_size[0] = 1 if password else 0  # 第一个字节标记是否加密
    
    # 明确使用小端序存储数据大小(取3个字节，最大支持16MB)
    size_bytes = struct.pack('<I', data_size)
    flag_and_size[1:4] = size_bytes[0:3]
    
    print(f"[隐藏] 标记加密: {'是' if password else '否'}")
    print(f"[隐藏] 数据大小标志: {flag_and_size.hex()}")
    
    # 隐藏标志和大小
    for i in range(4):
        byte = flag_and_size[i]
        for bit_idx in range(8):
            bit = (byte >> bit_idx) & 1
            pixel_idx = indices[i * 8 + bit_idx]
            # 设置像素字节的最低有效位
            pixel_data[pixel_idx] = (pixel_data[pixel_idx] & 0xFE) | bit
    
    # 隐藏实际数据
    for i in range(data_size):
        byte = data[i]
        for bit_idx in range(8):
            bit = (byte >> bit_idx) & 1
            pixel_idx = indices[32 + i * 8 + bit_idx]  # 32是前面标志和大小使用的位数
            # 设置像素字节的最低有效位
            pixel_data[pixel_idx] = (pixel_data[pixel_idx] & 0xFE) | bit
    
    # 写入隐藏了数据的BMP文件
    with open(output_image_path, 'wb') as f:
        f.write(header)
        f.write(pixel_data)
    
    print(f"成功隐藏 {data_size} 字节{'加密' if password else ''}数据到图像中")
    return True


def extract_data(stego_image_path, output_data_path, password=None):
    """
    从BMP图像中提取隐藏的数据
    
    Args:
        stego_image_path: 包含隐藏数据的BMP图像路径
        output_data_path: 提取数据保存的路径
        password: 如果数据已加密，提供解密密码
    """
    # 读取包含隐藏数据的BMP图像
    with open(stego_image_path, 'rb') as f:
        bmp_header = f.read(54)  # BMP文件头通常为54字节
        
        # 解析BMP文件头
        offset = struct.unpack('<I', bmp_header[10:14])[0]
        width = struct.unpack('<I', bmp_header[18:22])[0]
        height = struct.unpack('<I', bmp_header[22:26])[0]
        
        # 定位到像素数据
        f.seek(offset)
        pixel_data = f.read()
    
    # 计算种子值
    seed = width * height
    if password:
        # 如果有密码，将密码哈希添加到种子
        seed += int(hashlib.md5(password.encode()).hexdigest(), 16) % 10000000
    
    # 首先提取标志和数据大小（4字节）
    flag_and_size = bytearray(4)
    
    # 获取用于分布数据的索引
    indices = generate_indices(seed, len(pixel_data), 100000)  # 初始只获取足够多的索引
    
    # 提取标志和大小字节
    for i in range(4):
        byte_value = 0
        for bit_idx in range(8):
            pixel_idx = indices[i * 8 + bit_idx]
            if pixel_idx < len(pixel_data):
                bit = pixel_data[pixel_idx] & 1
                byte_value |= (bit << bit_idx)
        flag_and_size[i] = byte_value
    
    encrypted = flag_and_size[0] == 1
    
    # 正确解析数据大小(使用小端序)
    # 添加一个零字节，确保是32位整数
    size_bytes = bytes([flag_and_size[1], flag_and_size[2], flag_and_size[3], 0])
    data_size = struct.unpack('<I', size_bytes)[0]
    
    print(f"[提取] 检测到数据大小: {data_size} 字节")
    print(f"[提取] 数据是否加密: {'是' if encrypted else '否'}")
    print(f"[提取] 数据大小标志原始字节: {flag_and_size.hex()}")
    
    # 验证数据大小的合理性
    if data_size > len(pixel_data) // 8 or data_size <= 0:
        print(f"错误: 检测到的数据大小 ({data_size} 字节) 不合理")
        return False
    
    # 检查如果数据加密了但没有提供密码
    if encrypted and not password:
        print("错误: 数据已加密，请提供密码")
        return False
    
    # 如果需要更多索引，重新生成
    if 32 + data_size * 8 > len(indices):
        indices = generate_indices(seed, len(pixel_data), 32 + data_size * 8)
    
    # 提取实际数据
    extracted_data = bytearray(data_size)
    for i in range(data_size):
        byte_value = 0
        for bit_idx in range(8):
            pixel_idx = indices[32 + i * 8 + bit_idx]
            if pixel_idx < len(pixel_data):
                bit = pixel_data[pixel_idx] & 1
                byte_value |= (bit << bit_idx)
        extracted_data[i] = byte_value
    
    print(f"[提取] 从图像中提取的{'加密' if encrypted else ''}数据大小: {len(extracted_data)} 字节")
    
    # 如果数据已加密，尝试解密
    if encrypted:
        decrypted_data = decrypt_data(extracted_data, password)
        if not decrypted_data:
            return False
        extracted_data = decrypted_data
    
    # 保存提取的数据
    with open(output_data_path, 'wb') as f:
        f.write(extracted_data)
    
    print(f"成功从图像中提取 {len(extracted_data)} 字节数据")
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
    usable_bytes = max_bytes - 8  # 减去用于存储标志和大小的字节
    
    # 计算理论上可以隐藏的最大数据量(考虑加密后数据会变大)
    theoretical_max = usable_bytes
    encrypted_max = (theoretical_max - 32) // 1.05  # 考虑加密后会有约5%的膨胀，加上IV和salt的32字节
    
    print(f"BMP图像信息:")
    print(f"  宽度: {width}像素")
    print(f"  高度: {height}像素")
    print(f"  色深: {bit_depth}位")
    print(f"  像素数据大小: {pixel_data_size}字节")
    print(f"  最大可隐藏数据(无加密): {theoretical_max}字节 ({theoretical_max/1024:.2f}KB)")
    print(f"  最大可隐藏数据(加密): 约{int(encrypted_max)}字节 ({encrypted_max/1024:.2f}KB)")
    
    print("\n提高隐藏信息量的建议:")
    print("  1. 使用较大分辨率的BMP图像")
    print("  2. 使用24位或32位色深的图像")
    print("  3. 可以考虑使用LSB+技术在每个像素的多个位平面上隐藏数据")
    print("  4. 使用可变长度编码压缩数据后再隐藏")
    
    return theoretical_max


def main():
    parser = argparse.ArgumentParser(description='增强版BMP图像隐写工具')
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # 隐藏命令
    hide_parser = subparsers.add_parser('hide', help='隐藏数据到BMP图像')
    hide_parser.add_argument('-i', '--input', required=True, help='输入的BMP图像')
    hide_parser.add_argument('-d', '--data', required=True, help='需要隐藏的数据文件')
    hide_parser.add_argument('-o', '--output', required=True, help='输出的BMP图像')
    hide_parser.add_argument('-p', '--password', help='用于加密数据的密码(可选)')
    
    # 提取命令
    extract_parser = subparsers.add_parser('extract', help='从BMP图像中提取数据')
    extract_parser.add_argument('-i', '--input', required=True, help='包含隐藏数据的BMP图像')
    extract_parser.add_argument('-o', '--output', required=True, help='提取数据的输出文件')
    extract_parser.add_argument('-p', '--password', help='用于解密数据的密码(如果数据已加密)')
    
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
        hide_data(args.input, args.data, args.output, args.password)
    
    elif args.command == 'extract':
        if not os.path.exists(args.input):
            print(f"错误: 输入图像 '{args.input}' 不存在")
            return
        extract_data(args.input, args.output, args.password)
    
    elif args.command == 'analyze':
        if not os.path.exists(args.input):
            print(f"错误: 输入图像 '{args.input}' 不存在")
            return
        analyze_capacity(args.input)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main() 