# BMP图像隐写术工具

这个工具提供了将任意数据文件隐藏到BMP格式图像中的功能，实现了基于最低有效位(LSB)的隐写术。

## 功能特点

- 基础版 (`stego.py`): 简单的LSB隐写，将数据顺序隐藏在图像像素的最低位
- 增强版 (`enhanced_stego.py`): 
  - 支持密码保护(AES-256加密)
  - 使用伪随机数分散数据，提高安全性
  - 提供数据容量分析功能

## 安装要求

1. Python 3.6+
2. 对于增强版，需要额外安装PyCryptodome库:

```bash
pip install pycryptodome
```

## 使用方法

### 基础版

#### 隐藏数据
```bash
python stego.py hide -i input.bmp -d secret.txt -o output.bmp
```
python stego_bmp/stego.py hide -i pic-01.bmp -d text.txt  -o output-01.bmp
#### 提取数据
```bash
python stego.py extract -i output.bmp -o extracted_secret.txt
```
python stego_bmp/stego.py extract -i output-01.bmp -o extracted_secret.txt
#### 分析容量
```bash
python stego.py analyze -i input.bmp
python stego_bmp/stego.py analyze -i pic-01.bmp
```

### 增强版 

#### 隐藏数据(加密可选)
```bash
# 不加密
python enhanced_stego.py hide -i input.bmp -d secret.txt -o output.bmp
python stego_bmp/enhanced_stego.py hide -i pic-01.bmp -d text.txt -o output-02.bmp
# 使用密码加密
python enhanced_stego.py hide -i pic-01.bmp -d text.txt -o output-02.bmp -p PasswordJavis
python stego_bmp/enhanced_stego.py hide -i pic-02.bmp -d text.txt -o output-03.bmp -p javis
```

#### 提取数据
```bash
# 从未加密的图像中提取
python enhanced_stego.py extract -i output.bmp -o extracted_secret.txt
python stego_bmp/enhanced_stego.py extract -i output-02.bmp -o extracted_secret-01.txt

# 从加密的图像中提取
python enhanced_stego.py extract -i output.bmp -o extracted_secret.txt -p your_password
python stego_bmp/enhanced_stego.py extract -i output-03.bmp -o extracted_secret-02.txt -p javis
```

#### 分析容量
```bash
python enhanced_stego.py analyze -i input.bmp
python stego_bmp/enhanced_stego.py analyze -i pic-02.bmp
```

## 隐写原理

该工具基于图像隐写术的最低有效位(LSB)方法，将要隐藏的数据嵌入到BMP图像像素数据的最低位。由于人眼对最低位的变化不敏感，这种修改通常不会被肉眼察觉。

### 基础版隐写流程

1. 将数据大小(4字节)隐藏在图像开头
2. 将数据按顺序逐字节隐藏，每个字节拆分为8位，分别嵌入8个像素的最低位

### 增强版隐写流程

1. 可选择使用AES-256加密数据
2. 生成基于图像尺寸和可选密码的伪随机数作为种子
3. 使用伪随机数生成器确定数据分散的位置，提高安全性
4. 隐藏加密标志和数据大小
5. 将数据分散存储在图像中

## 安全考虑

- 避免使用过小的图像，以确保有足够空间隐藏数据
- 使用增强版+密码保护提供更高的安全性
- 使用24位或32位色深的图像获得更好的隐藏效果
- 考虑压缩数据后再隐藏以增加隐藏容量

## 局限性

- 仅支持BMP格式图像
- 如果图像被压缩或修改，隐藏的数据可能丢失
- 隐藏大量数据可能会导致图像质量轻微下降或可能被专业工具检测