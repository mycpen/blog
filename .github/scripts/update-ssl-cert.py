"""
    更新 SSL 证书。需数据脱敏
    - 证书: *.cpen.top
    - OHTTPS: https://ohttps.com/monitor/certificates

    - 云服务器: https://www.aliyun.com/
    - 多吉云: https://console.dogecloud.com/cdn/cert

"""

# =============================================================================
# 证书过期天数 > 10 天，不执行
import ssl
import socket
from datetime import datetime

def check_ssl_expiry(domain):
    try:
        # 建立SSL连接
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # 获取证书信息
                cert = ssock.getpeercert()
                # 获取证书过期日期
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                # 获取当前日期
                current_date = datetime.utcnow()
                # 计算剩余天数
                remaining_days = (expiry_date - current_date).days
                # 返回剩余天数
                return remaining_days
    except Exception as e:
        print(f"Error checking SSL expiry: {e}")
        return None

# 检测域名的SSL证书过期天数
domain = "cpen.top"
remaining_days = check_ssl_expiry(domain)
if remaining_days is not None:
    print(f"The SSL certificate for {domain} will expire in {remaining_days} days.")
if remaining_days is None or remaining_days > 10:
    raise SystemExit



# =============================================================================
# 获取 OHTTPS SSL 证书信息
# https://ohttps.com/docs/cloud/api/api
import hashlib
import time
import requests
import json
import os

# https://ohttps.com/monitor/cloudservers/4534
# 部署节点Id
apiId = os.environ["OHTTPS_APIID"]
# API接口密钥
apiKey = os.environ["OHTTPS_APIKEY"]
# 目标证书ID
certificateId = os.environ["OHTTPS_CERTIFICATEID"]

# 当前ms时间戳
timestamp = int(time.time() * 1000)
# 用于请求的参数列表
params = ["apiId=" + apiId, "timestamp=" + str(timestamp), "certificateId=" + certificateId]
# 用于签名的参数列表：用于请求的参数列表 + API接口密钥
paramsForSign = params + ["apiKey=" + apiKey]
# 用于签名的参数列表使用字母序进行排序
paramsForSign.sort()
# 用于签名的参数列表使用"&"号进行拼接成用以签名的字符串
stringForSign = "&".join(paramsForSign)
# 以上字符串的32位小写MD5哈希值即为参数签名
sign = hashlib.md5(stringForSign.encode('utf-8')).hexdigest()
# 接口最终请求地址
# 注意最终请求的参数中不包含apiKey
url = f"https://ohttps.com/api/open/getCertificate?sign={sign}&{'&'.join(params)}"
response = requests.get(url)
data = response.text
json_data = json.loads(data)

# # https://ohttps.com/monitor/certificates/20461
certKey = json_data['payload']['certKey']               # 私钥文件 cert.key        RSA PRIVATE KEY
fullChainCerts = json_data['payload']['fullChainCerts'] # 证书文件 fullchain.cer   CERTIFICATE



# =============================================================================
# 多吉云 SDK    blog.cpen.top
# https://docs.dogecloud.com/cdn/sdk-full-python
# https://github.com/mycpen/blog/blob/main/.github/scripts/refresh-dogecloud.py
from hashlib import sha1
import hmac
import requests
import json
import urllib
import os

# 多吉云
# 代码参考 https://docs.dogecloud.com/cdn/api-access-token?id=python
def dogecloud_api(api_path, data={}, json_mode=False):

    # 这里替换为你的多吉云永久 AccessKey 和 SecretKey，可在用户中心 - 密钥管理中查看
    # 请勿在客户端暴露 AccessKey 和 SecretKey，否则恶意用户将获得账号完全控制权
    access_key = os.environ["ACCESS_KEY"]
    secret_key = os.environ["SECRET_KEY"]

    body = ''
    mime = ''
    if json_mode:
        body = json.dumps(data)
        mime = 'application/json'
    else:
        body = urllib.parse.urlencode(data) # Python 2 可以直接用 urllib.urlencode
        mime = 'application/x-www-form-urlencoded'
    sign_str = api_path + "\n" + body
    signed_data = hmac.new(secret_key.encode('utf-8'), sign_str.encode('utf-8'), sha1)
    sign = signed_data.digest().hex()
    authorization = 'TOKEN ' + access_key + ':' + sign
    response = requests.post('https://api.dogecloud.com' + api_path, data=body, headers = {
        'Authorization': authorization,
        'Content-Type': mime
    })
    return response.json()

# 代码参考 https://docs.dogecloud.com/cdn/sdk-full-python?id=证书管理
# 上传证书; 加速域名绑定证书
# https://docs.dogecloud.com/cdn/sdk-full-python?id=上传证书
api = dogecloud_api('/cdn/cert/upload.json', {
    "note": "*.cpen.top",
    "cert": fullChainCerts, # CERTIFICATE
    "private": certKey      # RSA PRIVATE KEY
})
if api['code'] == 200:
    # print(api['data']['id'])
    main_cert_id = api['data']['id']    # 保存此证书 id，用于下方删除无用证书
    # 为加速域名绑定证书，blog.cpen.top 绑定此证书
    # https://docs.dogecloud.com/cdn/sdk-full-python?id=为加速域名绑定证书
    api = dogecloud_api('/cdn/domain/config.json?domain=blog.cpen.top', {
        # 'cert_id': api['data']['id']
        'cert_id': main_cert_id
    }, True)
    # api['code'] == 200 则成功，否则失败，失败请参考 api['msg'] 判断
    # 同上，cpen.top、www.cpen.top 绑定此证书
    api = dogecloud_api('/cdn/domain/config.json?domain=cpen.top', {
        # 'cert_id': api['data']['id']
        'cert_id': main_cert_id
    }, True)
    # api['code'] == 200 则成功，否则失败，失败请参考 api['msg'] 判断
    api = dogecloud_api('/cdn/domain/config.json?domain=www.cpen.top', {
        # 'cert_id': api['data']['id']
        'cert_id': main_cert_id
    }, True)
    # api['code'] == 200 则成功，否则失败，失败请参考 api['msg'] 判断
else:
    print("api failed: " + api['msg']) # 失败

# 删除无用证书
# https://docs.dogecloud.com/cdn/sdk-full-python?id=删除证书
api = dogecloud_api('/cdn/cert/list.json')  # 获取证书列表  https://docs.dogecloud.com/cdn/sdk-full-python?id=获取证书列表
if api['code'] == 200:
    for cert in api['data']['certs']:
        # print(cert)   # 获取证书列表
        # 删除非此id的证书。注：不会删除绑定了CDN加速域名的证书，参考自 https://docs.dogecloud.com/cdn/api-cert-delete
        if cert['id'] != main_cert_id:
            # 删除证书  https://docs.dogecloud.com/cdn/sdk-full-python?id=删除证书
            api = dogecloud_api('/cdn/cert/delete.json', {
                'id': cert['id']
            })
else:
    print("api failed: " + api['msg']) # 失败



# =============================================================================
# 因 阿里云服务器 2025-05-23 过期，而全文注释
# # 阿里云服务器  cpen.top
# import paramiko

# ali_password = os.environ["ALI_PASSWORD"]   # 阿里云 密码
# ali_ip = os.environ["ALI_IP"]               # 阿里云 IP

# filename_key = "cpen.top.key"
# content_key = certKey
# with open(filename_key, "w") as file_key:
#     file_key.write(content_key)

# filename_pem = "cpen.top.pem"
# content_pem = fullChainCerts
# with open(filename_pem, "w") as file_pem:
#     file_pem.write(content_pem)

# # 上传证书
# def transfer_files_to_remote(local_files, remote_directory, hostname, username, password):
#     # 创建SSH客户端
#     client = paramiko.SSHClient()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     try:
#         # 连接到远程服务器
#         client.connect(hostname=hostname, username=username, password=password)
#         # 创建SFTP客户端
#         sftp = client.open_sftp()
#         # 逐个传输文件
#         for local_file in local_files:
#             remote_file = remote_directory + '/' + local_file.split('/')[-1]
#             sftp.put(local_file, remote_file)
#         print("文件传输成功！")
#     except Exception as e:
#         print("文件传输失败:", str(e))
#     finally:
#         # 关闭SFTP客户端和SSH连接
#         sftp.close()
#         client.close()

# # 执行命令
# def execute_remote_command(hostname, username, password, command):
#     # 创建SSH客户端
#     client = paramiko.SSHClient()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     try:
#         # 连接到远程服务器
#         client.connect(hostname=hostname, username=username, password=password)
#         # 执行远程命令
#         stdin, stdout, stderr = client.exec_command(command)
#         # 打印命令执行结果
#         print("命令执行结果:")
#         print(stdout.read().decode())
#     except Exception as e:
#         print("命令执行失败:", str(e))
#     finally:
#         # 关闭SSH连接
#         client.close()

# remote_username = "root"
# remote_hostname = ali_ip
# remote_password = ali_password

# local_files = [f"{filename_key}", f"{filename_pem}"]
# remote_directory = "/usr/local/nginx/ssl"
# transfer_files_to_remote(local_files, remote_directory, remote_hostname, remote_username, remote_password)

# remote_command = "/usr/local/nginx/sbin/nginx -s reload"
# execute_remote_command(remote_hostname, remote_username, remote_password, remote_command)



# =============================================================================
