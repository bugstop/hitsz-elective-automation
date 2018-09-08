# Isaac Li
# 6.13.2018

import urllib.parse
from PIL import Image
from random import randint
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
import os
import json
import time
import base64
import requests
import warnings

warnings.filterwarnings("ignore")


class Encrypt(object):
    def __init__(self, key):
        self.key = key

    @staticmethod
    def add_to_16(value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)

    def encrypt_oracle(self, texts):
        """AES + base64."""
        aes = AES.new(Encrypt.add_to_16(self.key), AES.MODE_ECB)
        encrypt_aes = aes.encrypt(Encrypt.add_to_16(texts))
        encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')
        return encrypted_text

    def decrypt_oracle(self, texts):
        """Base 64 + AES."""
        aes = AES.new(Encrypt.add_to_16(self.key), AES.MODE_ECB)
        base64_decrypted = base64.decodebytes(texts.encode(encoding='utf-8'))
        decrypted_text = str(aes.decrypt(base64_decrypted), encoding='utf-8')
        return decrypted_text


conn = requests.session()

homepage = "http://jwts.hitsz.edu.cn/"
h = conn.get(homepage)
code_url = "http://jwts.hitsz.edu.cn/captchaImage"
code_img = conn.get(code_url)
with open('code.png', 'wb') as file:
    file.write(code_img.content)
Image.open('code.png').show()
code = input('code -> ')
os.remove('code.png')

try:
    with open("jw.json") as f_obj:
        [username_e, password_e] = json.load(f_obj)
        pwd = Encrypt('IsaacLi_HITsz')
        username = pwd.decrypt_oracle(username_e).split('\x00')[0]
        password = pwd.decrypt_oracle(password_e).split('\x00')[0]
except FileNotFoundError:
    print("\nYou only need to fill in once:")
    username = input("username -> ")
    password = input("password -> ")
    with open("jw.json", 'w') as f_obj:
        pwd = Encrypt('IsaacLi_HITsz')
        username_e = pwd.encrypt_oracle(username)
        password_e = pwd.encrypt_oracle(password)
        json.dump([username_e, password_e], f_obj)

headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Length': str(25 + len(username) + len(password) + len(code)),
    'Content-Type': 'application/x-www-form-urlencoded',
    'Host': 'jwts.hitsz.edu.cn',
    'Origin': 'http://jwts.hitsz.edu.cn',
    'Referer': 'http://jwts.hitsz.edu.cn/',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/67.0.3396.79 Safari/537.36'
}
postData = {
    'usercode': username,
    'password': password,
    'code': code
}

login = 'http://jwts.hitsz.edu.cn/login'
response = conn.post(login, data=postData, headers=headers)
html = response.content.decode("utf-8")

if "用户在使用本平台的过程中" in html:
    print("Sign in successfully.\n")
else:
    print('Error!')
    exit(233)

headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    'Cache-Control': 'max-age=0',
    'Content-Length': '106',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Host': 'jwts.hitsz.edu.cn',
    'Origin': 'http://jwts.hitsz.edu.cn',
    'Proxy-Connection': 'keep-alive',
    'Referer': 'http://jwts.hitsz.edu.cn/xsxk/queryXsxkList',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/67.0.3396.79 Safari/537.36}'
}
postData = {
    'rwh': '',
    'zy': '',
    'qz': '',
    'token': '0.34460906410023906',
    'pageXklb': 'qxrx',
    'pageXnxq': '2017-20183',
    'pageKkxiaoqu': '',
    'pageKkyx': '',
    'pageKcmc': ''
}

class_list = 'http://jwts.hitsz.edu.cn/xsxk/queryXsxkList'
response = conn.post(class_list, data=postData, headers=headers)
text = response.content

html = text.decode("utf-8")

soup = BeautifulSoup(html)
table = soup.find_all('table')[-1]
# print(table.prettify())
table_list = []
for string in table.strings:
    text = repr(string)
    if not any(['\\' in text, text == "'◇'", text == "'选   课'"]) or "/" in text:
        table_list.append(text[1:-1])
group_list = []
for i in range(int(table_list[-13]) + 1):
    group = []
    for j in range(13):
        group.append(table_list[13 * i + j])
    group_list.append(group)

for group in group_list[1:]:
    for index in [0, -1, 1, 2]:
        if index != -1:
            print('%2s' % group[index], end=' ')
        else:
            remaining = group[-1]
            space = 8
            for letter in remaining:
                if letter.isdigit() or letter == '/':
                    print(letter, end='')
                    space -= 1
            print(' ' * space, end='')
    print('')

code = input("\n选择课程序号，输入 0 退出：")
if code == '0' or not code.isdigit():
    exit(888)
else:
    group = group_list[int(code)]
    print("You choose:", end=' ')

    for index in [-1, 1, 2, -3, -2, 5]:
        if index == 5:
            print('\n' + ' ' * 12 + group[index])
        elif index == -1:
            remaining = group[-1]
            for letter in remaining:
                if letter.isdigit() or letter == '/':
                    print(letter, end='')
            print(' ', end='')
        else:
            print('%2s' % group[index], end=' ')

    cancel = input("按回车键确认，任意键退出：")
    if cancel:
        exit(999)

print("\nConfirmed.\n")

while True:
    class_list = 'http://jwts.hitsz.edu.cn/xsxk/queryXsxkList'
    response = conn.post(class_list, data=postData, headers=headers)
    text = response.content
    html = text.decode("utf-8")
    soup = BeautifulSoup(html)
    table = soup.find_all('table')[-1]
    table_list = []
    for string in table.strings:
        text = repr(string)
        if not any(['\\' in text, text == "'◇'", text == "'选   课'"]) or "/" in text:
            table_list.append(text[1:-1])
    group_list = []
    for i in range(int(table_list[-13]) + 1):
        group = []
        for j in range(13):
            group.append(table_list[13 * i + j])
        group_list.append(group)
    group = group_list[int(code)]

    remaining = group[-1]
    available = ''
    for letter in remaining:
        if letter.isdigit() or letter == '/':
            print(letter, end='')
            available += letter
    available_total = available.split('/')
    current = time.strftime('%H:%M:%S', time.localtime(time.time()))
    print(time.strftime(f" at {current}"))

    token = soup.find_all(id="token")[0]["value"]

    if int(available_total[0]) < int(available_total[1]):
        print(f"\nAvailable! {current}\n")

        headers = {
            'Host': 'jwts.hitsz.edu.cn',
            'Content-Length': '129',
            'Cache-Control': 'max-age=0',
            'Origin': 'http://jwts.hitsz.edu.cn',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/67.0.3396.79 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Referer': 'http://jwts.hitsz.edu.cn/xsxk/queryXsxkList',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        postData = {
            'rwh': f'2017-2018-3-{group[1]}-001',
            'zy': '',
            'qz': '',
            'token': token,
            'pageXklb': 'qxrx',
            'pageXnxq': '2017-20183',
            'pageKkxiaoqu': '',
            'pageKkyx': '',
            'pageKcmc': ''
        }

        postData = urllib.parse.urlencode(postData).encode('utf-8')
        class_list = 'http://jwts.hitsz.edu.cn/xsxk/saveXsxk'
        rep = conn.post(class_list, data=postData, headers=headers)
        response = rep.content.decode("utf-8")
        print('选课结果：')
        if '不在学生选课时间范围内' in response:
            print('不在选课时间范围内！\n')
            time.sleep(10)
            continue
        elif '冲突' in response:
            print('时间冲突！\n')
        else:
            print('我感觉应该选上了？')

        get = input(f"\n请确认是否选上{group[2]}，\n按回车键退出，输入其他内容则继续：")
        if not get:
            exit(666)

    hour = int(time.strftime('%H', time.localtime(time.time())))
    slow = list(range(0, 8)) + [23]
    fast = list(range(10, 14)) + list(range(18, 22))
    if hour in fast:
        wait = 10
    elif hour in slow:
        wait = 60
    else:
        wait = 20
    wait += randint(0, 5)
    time.sleep(wait)
