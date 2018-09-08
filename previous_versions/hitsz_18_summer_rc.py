# Isaac Li
# 6.14.2018

import gzip
import json
import time
import base64
import warnings
import urllib.parse
import urllib.request
import http.cookiejar
from PIL import Image
from random import randint
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from win10toast import ToastNotifier

warnings.filterwarnings("ignore")


class Encrypt(object):
    """Encrypt text with key in method AES-ECB."""

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
    """All data needed in a post."""

    def __init__(self, url):
        self.url = url
        self.response = None
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
            'Cache-Control': 'max-age=0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'jwts.hitsz.edu.cn',
            'Origin': 'http://jwts.hitsz.edu.cn',
            'Referer': 'http://jwts.hitsz.edu.cn/xsxk/queryXsxkList',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/67.0.3396.79 Safari/537.36'
        }
        self.data = {
            'zy': '',
            'qz': '',
            'pageXklb': 'qxrx',
            'pageXnxq': term[0] + term[1],
            'pageKkxiaoqu': '',
            'pageKkyx': '',
            'pageKcmc': ''
        }

    def post(self):
        """
        Post executed.
        :return: html text in the response.
        """
        post_data = urllib.parse.urlencode(self.data).encode('utf-8')
        self.headers['Content-Length'] = str(len(post_data))
        request = urllib.request.Request(self.url, post_data, self.headers)
        response = opener.open(request)
        html = response.read()
        text = gzip.decompress(html).decode("utf-8")
        self.response = text


def sign_in():
    """Sign in to the system."""

    def get_user():
        """
        Load username and password from file 'jw.json'.
        If not existing, create a new one.
        :return: decrypted username and password.
        """
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

    # Visit homepage to set cookies.
    opener.open(homepage)
    code_img = opener.open(code_url)
    Image.open(code_img).show()
    code_text = input('code -> ')

    username, password = get_user()
    login = Post(login_page)
    login.headers['Referer'] = homepage
    login.data = {
        'usercode': username,
        'password': password,
        'code': code_text
    }
    login.post()

    if "用户在使用本平台的过程中" not in login.response:
        raise RuntimeError('Login Error!')


def main():
    """To take a elective course."""

    def class_index():
        """List all courses in the page."""

        listing = Post(class_list)
        listing.data['rwh'] = ''
        listing.data['token'] = ''
        listing.post()

        listing_response = BeautifulSoup(listing.response)
        class_table = listing_response.find_all('table')[-1]

        # 瞎筛的
        table_text = []
        for strings in class_table.strings:
            string_text = repr(strings)
            if "/" in string_text or \
                    not any(['\\' in string_text,
                             string_text == "'◇'",
                             string_text == "'选   课'"]):
                table_text.append(string_text[1:-1])

        groups_text = []
        for _i in range(int(table_text[-13]) + 1):
            group_text = []
            for _j in range(13):
                group_text.append(table_text[13 * _i + _j])
            groups_text.append(group_text)

        token_value = listing_response.find_all(id="token")[0]["value"]
        return groups_text, token_value

    def print_info(subject, nums):
        """
        Show more details of a course.
        :param subject: chosen course
        :param nums: indexes of the attributes
        :return: None
        """
        for num in nums:
            if num == 5:  # 排课时间
                print('\n' + ' ' * 12 + subject[num])
            elif num == -1:  # 课程余量
                info, space = subject[-1], 8
                for each in info:
                    if each.isdigit() or each == '/':
                        print(each, end='')
                        space -= 1
                print(' ' * space, end='')
            else:
                print('%2s' % subject[num], end=' ')

    def set_interval():
        """
        Set the interval seconds depending on the current time.
        :return: seconds
        """
        hour = int(time.strftime('%H', time.localtime(time.time())))
        slow = list(range(0, 8)) + [23]
        fast = list(range(10, 14)) + list(range(18, 22))

        if hour in fast:
            interval = 10
        elif hour in slow:
            interval = 60
        else:
            interval = 20

        interval += randint(0, 5)
        return interval

    group_list, _ = class_index()
    for group in group_list[1:]:
        print_info(group, [0, -1, 1, 2])
        print('')

    class_number = input("\n选择课程序号，输入 0 退出程序：")
    if class_number == '0' or not class_number.isdigit():
        exit(0)
    else:
        group = group_list[int(class_number)]
        print("You choose:", end=' ')
        print_info(group, [-1, 1, 2, -3, -2, 5])
        cancel = input("按回车键确认，任意键退出程序：")
        if cancel:
            exit(0)
        else:
            print("\nConfirmed.\n")

    while True:
        group_list, token = class_index()
        selected = group_list[int(class_number)]

        remaining, available = selected[-1], ''
        for letter in remaining:
            if letter.isdigit() or letter == '/':
                print(letter, end='')
                available += letter
        available_total = available.split('/')

        current = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print(time.strftime(f" at {current}"))

        if int(available_total[0]) < int(available_total[1]):
            print(f"\nAvailable! {current}\n")

            elective = Post(class_action)
            elective.data['rwh'] = f'{term[0]}-{term[1]}-{group[1]}-001'
            elective.data['token'] = token
            elective.post()

            print('选课结果：')
            if '不在学生选课时间范围内' in elective.response:
                print('不在选课时间范围内！\n')
                time.sleep(10)
                continue
            elif '时间冲突' in elective.response:
                print('时间冲突！\n')
                ToastNotifier().show_toast('选课通知', '时间冲突，请退选冲突课程后重试！')
                break
            else:
                ToastNotifier().show_toast('选课通知', '选课成功，请尽快确认是否已选中。')

            get = input(f"请确认是否选上《{group[2]}》\n按回车键将重试，输入其他内容则完成本次选课：")
            if get:
                break

        wait = set_interval()
        time.sleep(wait)


term = ('2017-2018', '3')

homepage = "http://jwts.hitsz.edu.cn/"
login_page = 'http://jwts.hitsz.edu.cn/login'
code_url = "http://jwts.hitsz.edu.cn/captchaImage"
class_list = 'http://jwts.hitsz.edu.cn/xsxk/queryXsxkList'
class_action = 'http://jwts.hitsz.edu.cn/xsxk/saveXsxk'

cookie = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie))

while True:
    try:
        sign_in()
    except RuntimeError:
        print('Error!')
        continue
    else:
        print("Sign in successfully.\n")
        break
while True:
    main()
    stop = input('按回车键继续选其他课，输入其他内容退出程序：')
    print('')
    if stop:
        break
