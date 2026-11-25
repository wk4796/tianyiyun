#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2025/5/9 9:48
# 原作者：https://www.52pojie.cn/thread-1231190-1-1.html
# 出处：https://github.com/vistal8/tianyiyun
# cron "30 4 * * *" script-path=xxx.py,tag=匹配cron用
# const $ = new Env('天翼云盘签到');
# 变量说明：ty_username 用户名 &隔开  ty_password 密码 &隔开
# 5.9变更：更改推送为表格单次推送 打印日志简化
# 推送变量需设置 WXPUSHER_APP_TOKEN 和 WXPUSHER_UID（多个UID用&分隔）
# 新增Telegram推送变量：TELEGRAM_BOT_TOKEN 和 TELEGRAM_CHAT_ID（多个Chat ID用&分隔）
# 有图形验证码就是风控了 更换IP后尝试即可 自己去网页端登陆 输入验证码 再次尝试 如果还不行就只能静默几天
# 2026.05.28 上游修复登录接口错误（合并自 tianyiyun.py，感谢四点八哩）
# 2026.11.25 合并上游登录修复；抽奖活动已失效，移除抽奖功能；保留本版特色：Telegram推送 / WxPusher表格推送 / 手机号中段脱敏
import time
import os
import json
import base64
import rsa
import requests
import re
from urllib.parse import urlparse, parse_qs

BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 从环境变量获取账号信息
ty_usernames = os.getenv("ty_username").split('&') if os.getenv("ty_username") else []
ty_passwords = os.getenv("ty_password").split('&') if os.getenv("ty_password") else []

# 检查环境变量
if not ty_usernames or not ty_passwords:
    raise ValueError("❌ 请设置环境变量 ty_username 和 ty_password")

# 组合账号信息
accounts = [{"username": u, "password": p} for u, p in zip(ty_usernames, ty_passwords)]

# WxPusher配置
WXPUSHER_APP_TOKEN = os.getenv("WXPUSHER_APP_TOKEN")
WXPUSHER_UIDS = os.getenv("WXPUSHER_UID", "").split('&')

# Telegram配置
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_IDS = os.getenv("TELEGRAM_CHAT_ID", "").split('&')


def mask_phone(phone):
    """隐藏手机号中间四位"""
    return phone[:3] + "****" + phone[-4:] if len(phone) == 11 else phone[:3] + "****" + phone[-4:]

def int2char(a):
    return BI_RM[a]

def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = B64MAP.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d

def rsa_encode(j_rsakey, string):
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result

def login(username, password):
    print("🔄 正在执行登录流程...")
    s = requests.Session()
    try:
        urlToken = "https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
        r = s.get(urlToken)
        match = re.search(r"href\s*=\s*'([^']*autoLogin[^']*)'", r.text)
        if not match:
            print("❌ 错误：未找到动态登录页")
            return None

        auto_login_url = match.group(1)

        # 获取重定向URL以提取查询参数
        r = s.get(auto_login_url, allow_redirects=True)
        redirect_url = r.url  # 保存重定向最终URL

        # 从最终URL提取查询参数
        parsed = urlparse(r.url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # POST appConf.do 获取登录令牌
        r = s.post("https://open.e.189.cn/api/logbox/oauth2/wap/appConf.do", params=params, timeout=10)
        conf = r.json()
        if conf.get('result', '-1') != '0':
            print(f"❌ 错误：获取登录配置失败 - {conf.get('msg', '未知错误')}")
            return None

        data = conf['data']
        lt = data['lt']
        returnUrl = data['returnUrl']
        paramId = data['paramId']
        accountType = data.get('accountType', '02')
        s.headers.update({"lt": lt})

        # 获取login.html页面提取RSA密钥
        login_html_url = re.sub(r'/index\.html', '/login.html', redirect_url)
        r = s.get(login_html_url, timeout=10)
        match = re.search(r'id="j_rsaKey"\s+value="([^"]+)"', r.text)
        if not match:
            print("❌ 错误：获取RSA密钥失败")
            return None
        j_rsakey = match.group(1)

        username_enc = rsa_encode(j_rsakey, username)
        password_enc = rsa_encode(j_rsakey, password)

        data = {
            "appKey": "cloud",
            "accountType": accountType,
            "userName": f"{{RSA}}{username_enc}",
            "password": f"{{RSA}}{password_enc}",
            "validateCode": "",
            "captchaToken": "",
            "returnUrl": returnUrl,
            "mailSuffix": "@189.cn",
            "paramId": paramId
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
            'Referer': 'https://open.e.189.cn/',
        }

        r = s.post(
            "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do",
            data=data,
            headers=headers,
            timeout=10
        )

        result = r.json()
        if str(result.get('result', -1)) != '0':
            print(f"❌ 登录错误：{result.get('msg', '未知错误')}")
            return None

        if 'toUrl' not in result:
            print("❌ 错误：登录响应缺少 toUrl")
            return None
        s.get(result['toUrl'])

        print("✅ 登录成功")
        return s

    except Exception as e:
        print(f"⚠️ 登录异常：{str(e)}")
        return None

def send_wxpusher(msg):
    if not WXPUSHER_APP_TOKEN or not WXPUSHER_UIDS or all(uid == '' for uid in WXPUSHER_UIDS):
        print("⚠️ 未配置WxPusher，跳过消息推送")
        return

    url = "https://wxpusher.zjiecode.com/api/send/message"
    headers = {"Content-Type": "application/json"}
    for uid in WXPUSHER_UIDS:
        if not uid: # 跳过空的UID
            continue
        data = {
            "appToken": WXPUSHER_APP_TOKEN,
            "content": msg,
            "contentType": 3,
            "topicIds": [],
            "uids": [uid],
        }
        try:
            resp = requests.post(url, json=data, headers=headers, timeout=10)
            if resp.json().get('code') == 1000:
                print(f"✅ WxPusher消息推送成功 -> UID: {uid}")
            else:
                print(f"❌ WxPusher消息推送失败：{resp.text}")
        except Exception as e:
            print(f"❌ WxPusher推送异常：{str(e)}")

def send_telegram(results): # 接收 all_results 列表
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_IDS or all(chat_id == '' for chat_id in TELEGRAM_CHAT_IDS):
        print("⚠️ 未配置Telegram，跳过消息推送")
        return

    # 构建 Telegram 消息内容 (纯文本)
    telegram_msg_parts = ["⛅️ 天翼云盘签到汇总\n"] # 标题

    for i, res in enumerate(results):
        # 为每个账号添加一个分隔符，如果多于一个账号
        if i > 0:
            telegram_msg_parts.append("\n---\n") # 分隔线

        telegram_msg_parts.append(f"签到结果：{res['sign']}")

    final_telegram_msg = "".join(telegram_msg_parts)

    for chat_id in TELEGRAM_CHAT_IDS:
        if not chat_id: # 跳过空的Chat ID
            continue
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        headers = {"Content-Type": "application/json"}

        data = {
            "chat_id": chat_id,
            "text": final_telegram_msg,
            # 移除 parse_mode，默认即为纯文本
            # "parse_mode": "MarkdownV2" # 不再使用任何解析模式
        }
        try:
            resp = requests.post(url, json=data, headers=headers, timeout=10)
            if resp.json().get('ok'):
                print(f"✅ Telegram消息推送成功 -> Chat ID: {chat_id}")
            else:
                print(f"❌ Telegram消息推送失败：{resp.text}")
        except Exception as e:
            print(f"❌ Telegram推送异常：{str(e)}")


def main():
    print("\n=============== 天翼云盘签到开始 ===============")
    all_results = []

    for acc in accounts:
        username = acc["username"]
        password = acc["password"]
        masked_phone = mask_phone(username)
        account_result = {"username": masked_phone, "sign": ""}

        print(f"\n🔔 处理账号：{masked_phone}")

        # 登录流程
        session = login(username, password)
        if not session:
            account_result["sign"] = "❌ 登录失败"
            all_results.append(account_result)
            continue

        # 签到流程
        try:
            # 每日签到
            rand = str(round(time.time() * 1000))
            sign_url = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
                "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
                "Host": "m.cloud.189.cn",
            }
            resp = session.get(sign_url, headers=headers).json()
            if resp.get('isSign') == "false":
                account_result["sign"] = f"✅ +{resp.get('netdiskBonus', '?')}M"
            else:
                account_result["sign"] = f"⏳ 已签到+{resp.get('netdiskBonus', '?')}M"

        except Exception as e:
            account_result["sign"] = f"❌ 操作异常：{str(e)}"

        all_results.append(account_result)
        print(f"  {account_result['sign']}")

    # 生成WxPusher的汇总表格
    wxpusher_table = "### ⛅ 天翼云盘签到汇总\n\n"
    wxpusher_table += "| 账号 | 签到结果 |\n"
    wxpusher_table += "|:-:|:-:|\n"
    for res in all_results:
        wxpusher_table += f"| {res['username']} | {res['sign']} |\n"

    # 发送汇总推送
    send_wxpusher(wxpusher_table)
    send_telegram(all_results) # 将 all_results 列表传递给 send_telegram
    print("\n✅ 所有账号处理完成！")

if __name__ == "__main__":
    main()
