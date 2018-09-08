# Isaac Li
# 9.8.2018

import os
import json
import time
import base64
import warnings
import requests
import pytesseract
import urllib.parse
from PIL import Image
from random import randint
from bs4 import BeautifulSoup
from Crypto.Cipher import AES

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
        """Base64 + AES."""
        aes = AES.new(Encrypt.add_to_16(self.key), AES.MODE_ECB)
        base64_decrypted = base64.decodebytes(texts.encode(encoding='utf-8'))
        decrypted_text = str(aes.decrypt(base64_decrypted), encoding='utf-8')
        return decrypted_text


class Post(object):
    def __init__(self, url):
        self.url = url
        self.headers = {
            'Host': 'jwts.hitsz.edu.cn',
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
        self.data = {
            'zy': '',
            'qz': '',
            'pageXklb': 'qxrx',
            'pageXnxq': conf['term'][0] + conf['term'][1],
            'pageKkxiaoqu': '',
            'pageKkyx': '',
            'pageKcmc': ''
        }
        self.response = None

    def post(self):
        post_data = urllib.parse.urlencode(self.data).encode('utf-8')
        self.headers['Content-Length'] = str(len(post_data))
        response = opener.post(self.url, data=self.data, headers=self.headers)
        html = response.content.decode("utf-8")
        self.response = html


class Functions(object):
    @staticmethod
    def class_index():
        listing = Post(conf['class_list'])
        listing.data['rwh'] = ''
        listing.data['token'] = ''
        listing.post()

        listing_response = BeautifulSoup(listing.response)
        class_table = listing_response.find_all('table')[-1]
        soup = BeautifulSoup(repr(class_table))
        table_text = []
        for index, tr in enumerate(soup.find_all('tr')):
            if index != 0:
                tds = tr.find_all('td')
                table_text.append({
                    '序号': tds[1].contents[0],
                    '课程代码': tds[2].contents[0],
                    '课程名称': tds[3].contents[0].contents[0],
                    '前置课程': tds[4].contents[0] if tds[4].contents else '',
                    '面向对象': tds[5].contents[0] if tds[5].contents else '',
                    '校区': tds[6].contents[0],
                    '上课信息': tds[7].contents[0].contents[3],
                    '课程类别': tds[8].contents[0],
                    '课程性质': tds[9].contents[0],
                    '开课院系': tds[10].contents[0],
                    '学分': tds[11].contents[0] + '学分',
                    '学时': tds[12].contents[0] + '学时',
                    '容量': ''.join(i if i.isdigit() or i == '/' else '' for i in tds[13].contents[-1]),
                })
        token_value = listing_response.find_all(id="token")[0]["value"]
        return table_text, token_value

    @staticmethod
    def print_info(subject, nums):
        for num in nums:
            if num == '上课信息':
                print('\n' + ' ' * 15 + subject[num])
            elif num == '容量_整整齐齐':
                a, b = subject['容量'].split('/')
                print('%3d/%-3d' % (int(a), int(b)), end=' ')
            else:
                print('%2s' % subject[num], end=' ')


def log_in_actions(auto):
    def get_user_info():
        try:
            with open("jw.json") as f_obj:
                [username_e, password_e] = json.load(f_obj)
                pwd = Encrypt('IsaacLi_HITsz')
                username_d = pwd.decrypt_oracle(username_e).split('\x00')[0]
                password_d = pwd.decrypt_oracle(password_e).split('\x00')[0]
        except FileNotFoundError:
            print("\nYou only need to fill in once:")
            username_d = input("username -> ")
            password_d = input("password -> ")
            with open("jw.json", 'w') as f_obj:
                pwd = Encrypt('IsaacLi_HITsz')
                username_e = pwd.encrypt_oracle(username_d)
                password_e = pwd.encrypt_oracle(password_d)
                json.dump([username_e, password_e], f_obj)
        return username_d, password_d

    def ocr(image):
        threshold, table = 140, []
        for i in range(256):
            if i < threshold:
                table.append(0)
            else:
                table.append(1)

        # letters to numbers
        rep = {'O': '0', 'I': '1', 'L': '1', 'B': '8',
               'C': '0', 'D': '0', 'E': '8', 'G': '6',
               'T': '7', 'Q': '0', 'A': '4', '.': '',
               'Z': '2', '&': '6', 'S': '8', ' ': ''}

        def number(img):
            img = img.convert('L')
            img = img.point(table, '1')
            text = pytesseract.image_to_string(img, config='-psm 7 digits')
            text = text.strip().upper()
            for r in rep:
                text = text.replace(r, rep[r])
            return text

        code = number(image)
        if not code or len(code) != 4:
            code = 'x'
        return code

    opener.get(conf['homepage'])
    username, password = get_user_info()

    if auto:
        while True:
            code_img = opener.get(conf['code_url']).content
            with open('code.png', 'wb') as file:
                file.write(code_img)
            code_text = ocr(Image.open('code.png'))
            if code_text.isdigit():
                print('自动识别验证码为：' + code_text, end='，')
                break
    else:
        code_img = opener.get(conf['code_url']).content
        with open('code.png', 'wb') as file:
            file.write(code_img)
        Image.open('code.png').show()
        code_text = input('请输入显示的验证码： ')
    os.remove('code.png')

    login = Post(conf['login_page'])
    login.headers['Referer'] = conf['homepage']
    login.data = {
        'usercode': username,
        'password': password,
        'code': code_text
    }
    login.post()

    if "用户在使用本平台的过程中" not in login.response:
        raise RuntimeError('登录失败！')


def log_in():
    flag = True
    while True:
        try:
            log_in_actions(flag)
        except RuntimeError as e:
            print(e)
            continue
        except KeyboardInterrupt:
            flag = False
            print('已选择手动输入验证码。')
            continue
        else:
            print("登入成功。\n")
            break


def list_info():
    group_list, _ = Functions.class_index()

    while True:
        for group in group_list:
            Functions.print_info(group, ['序号', '容量_整整齐齐', '课程代码', '课程名称'])
            print('')

        class_number = input("\n请选择课程序号：")
        if not (class_number.isdigit() and 1 <= int(class_number) <= len(group_list)):
            print("\n请输入正确的序号！\n")
            continue
        else:
            group = group_list[int(class_number) - 1]
            print("当前选择的课是：", end=' ')
            Functions.print_info(group, ['容量', '课程代码', '课程名称', '学分', '学时', '上课信息'])
            cancel = input("按回车键确认，否则重新选择：")
            if not cancel:
                print("\n已确认。\n")
                break
            else:
                print("\n")
                continue

    return int(class_number) - 1


def post_action(class_index):
    def set_interval():
        hour = int(time.strftime('%H', time.localtime(time.time())))
        slow = list(range(0, 8)) + [23]
        fast = list(range(10, 14)) + list(range(18, 22))
        if hour in fast:
            interval = 10
        elif hour in slow:
            interval = 40
        else:
            interval = 20
        interval += randint(0, interval / 5)
        return interval

    while True:
        group_list, token = Functions.class_index()
        selected = group_list[class_index]

        occupied, total = selected['容量'].split('/')
        status = '可选' if int(occupied) < int(total) else '已满'
        current = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print(f"【{status}】 {selected['容量']}，查询时间：{current}")

        if status == '可选':
            elective = Post(conf['class_action'])
            elective.data['rwh'] = f'{conf["term"][0]}-{conf["term"][1]}-{selected["课程代码"]}-001'
            elective.data['token'] = token
            elective.post()

            print('\n选课结果：')
            if '不在学生选课时间范围内' in elective.response:
                print('    不在选课时间范围内！\n')
                time.sleep(8)
                continue
            elif '时间冲突' in elective.response:
                print('    时间冲突！\n')
                break
            else:
                print('    我感觉应该选上了？\n')

            done = input(f"请确认是否选上{selected['课程名称']}，\n"
                         f"按回车键将重试，否则完成本次选课：")
            if done:
                break
        else:
            wait = set_interval()
            time.sleep(wait)


def hitsz():
    while True:
        log_in()
        index = list_info()
        try:
            post_action(index)
        except KeyboardInterrupt:
            print('已停止。')
        stop = input('按回车键继续选其他课，否则退出程序：')
        if stop:
            break


conf = {
    'term': ('2018-2019', '1'),
    'homepage': "http://jwts.hitsz.edu.cn/",
    'login_page': 'http://jwts.hitsz.edu.cn/login',
    'code_url': "http://jwts.hitsz.edu.cn/captchaImage",
    'class_list': 'http://jwts.hitsz.edu.cn/xsxk/queryXsxkList',
    'class_action': 'http://jwts.hitsz.edu.cn/xsxk/saveXsxk',
}

if __name__ == '__main__':
    opener = requests.session()
    hitsz()
