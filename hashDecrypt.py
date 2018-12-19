# -*- coding: utf-8 -*-  
import json
import re
import time
import pyperclip
import requests

# common
header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0'}

########################################################################################################################

# #cmd5.com接口解密hash
# def hashDecrypt_cmd5_com(hash):
#     resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
#     resultJson['source'] = 'cmd5.com'
#     hashData= {'__VIEWSTATE': '',
#                'ctl00$ContentPlaceHolder1$HiddenFieldAliCode':'',
#                'ctl00$ContentPlaceHolder1$HiddenField1':'',
#                'ctl00$ContentPlaceHolder1$HiddenField2':'',
#                'ctl00$ContentPlaceHolder1$TextBoxInput':hash,
#                'ctl00$ContentPlaceHolder1$Button1':'查询',
#                'ctl00$ContentPlaceHolder1$InputHashType':'md5',
#                '__VIEWSTATEGENERATOR':'CA0B0334'
#                }
#     url = 'https://cmd5.com/'
#     reHtml = requests.post(url=url,headers=header,data=hashData).content.decode()
#     # print(reHtml)
#
#     pattern = re.compile(r'id="__VIEWSTATE"(.*?) />',re.S)
#     VIEWSTATE = re.findall(pattern,reHtml)[0]
#     pattern = re.compile(r'value="(.*?)"',re.S)
#     VIEWSTATE = re.findall(pattern,VIEWSTATE)[0]
#     hashData['__VIEWSTATE'] = VIEWSTATE
#
#     pattern = re.compile(r'id="HiddenFieldAliCode"(.*?)/>', re.S)
#     HiddenFieldAliCode = re.findall(pattern, reHtml)[0].replace(' ','')
#     if HiddenFieldAliCode:
#         pattern = re.compile(r'value="(.*?)"', re.S)
#         HiddenFieldAliCode = re.findall(pattern, HiddenFieldAliCode)[0]
#         hashData['ctl00$ContentPlaceHolder1$HiddenFieldAliCode'] = HiddenFieldAliCode
#     print(HiddenFieldAliCode)
#
#     pattern = re.compile(r'id="ctl00_ContentPlaceHolder1_HiddenField1"(.*?)/>', re.S)
#     HiddenField1 = re.findall(pattern, reHtml)[0].replace(' ','')
#     if HiddenField1:
#         pattern = re.compile(r'value="(.*?)"', re.S)
#         HiddenField1 = re.findall(pattern, HiddenField1)[0]
#         hashData['ctl00$ContentPlaceHolder1$HiddenField1'] = HiddenField1
#     print(HiddenField1)
#
#     pattern = re.compile(r'id="ctl00_ContentPlaceHolder1_HiddenField2"(.*?)/>', re.S)
#     HiddenField2 = re.findall(pattern, reHtml)[0].replace(' ','')
#     if HiddenField2:
#         pattern = re.compile(r'value="(.*?)"', re.S)
#         HiddenField2 = re.findall(pattern, HiddenField2)[0]
#         hashData['ctl00$ContentPlaceHolder1$HiddenField2'] = HiddenField2
#     print(HiddenField2)
#     print(hashData)
#     reHtml = requests.post(url=url, headers=header, data=hashData).content.decode()
#     print(reHtml)

# somd5.com接口解密hash
def hashDecrypt_somd5_com(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'somd5.com'
    hashData= {'hash': ''}
    hashData['hash'] = hash
    url = "https://www.somd5.com/search.php"
    reJson = json.loads(requests.post(url=url,headers=header,data=hashData,timeout=60).content.decode())
    # print(reJson)
    if 'data' in reJson:
        resultJson['data'] = reJson['data']
    else:
        pass
    if reJson['err'] ==0:
        resultJson['text'] = '破解成功'
    elif reJson['err'] ==1:
        resultJson['text'] = '请输入密文'
    elif reJson['err'] ==2:
        resultJson['text'] = '此密文无法识别'
    elif reJson['err'] ==3:
        resultJson['text'] = '破解失败'
    elif reJson['err'] ==4:
        resultJson['text'] = 'err=4'
    elif reJson['err'] ==5:
        resultJson['text'] = '验证失败'
    resultJson['type'] = reJson['type']
    return resultJson

# md5decrypt.net接口解密hash
def hashDecrypt_md5decrypt_net(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'md5decrypt.net'
    if len(hash)== 32 :
        hash_type= 'md5'
    elif len(hash) == 40:
        hash_type = 'sha1'
    elif len(hash) == 64:
        hash_type = 'sha256'
    elif len(hash) == 96:
        hash_type = 'sha384'
    elif len(hash) == 128:
        hash_type = 'sha512'
    else:
        resultJson['text'] = '无法识别'
        return resultJson
    url = 'https://md5decrypt.net/en/Api/api.php?hash=' + hash + '&hash_type=' + hash_type + '&email=w666q@qq.com&code=c1eb4ed57d09e646'
    reHtml = requests.get(url=url,headers=header,timeout=60).content.decode()
    if reHtml: #如果返回结果不为空
        if reHtml == 'ERROR CODE : 001':
            resultJson['text'] = '每天超过400允许的请求'
        elif reHtml == 'ERROR CODE : 002':
            resultJson['text'] = '电子邮件/代码出错'
        elif reHtml == 'ERROR CODE : 003':
            resultJson['text'] = '请求包含400多个哈希值'
        elif reHtml == 'ERROR CODE : 004':
            resultJson['text'] = '参数hash_type中提供的哈希类型似乎无效'
        elif reHtml == 'ERROR CODE : 005':
            resultJson['text'] = '提供的哈希似乎与您设置的哈希类型不匹配'
        elif reHtml == 'ERROR CODE : 006':
            resultJson['text'] = '没有提供所有参数，或者错误地填写了其中一个参数'
        elif reHtml == 'ERROR CODE : 007':
            resultJson['text'] = '输入的高级代码似乎无效'
        elif reHtml == 'ERROR CODE : 008':
            resultJson['text'] = '高级变量似乎不正确，必须为1'
        elif reHtml == 'ERROR CODE : 009':
            resultJson['text'] = '高级帐户已用完，要继续使用它，您必须买更多时间'
        else:
            resultJson['text'] = '破解成功'
    else: #如果返回结果为空
        resultJson['text'] = '破解失败'
    resultJson['data'] = reHtml.replace('\n','')
    resultJson['type'] = hash_type
    return resultJson

#hashtoolkit.com接口解密hash
def hashDecrypt_hashtoolkit_com(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'hashtoolkit.com'
    url = 'http://hashtoolkit.com/reverse-hash?hash=' + hash
    reHtml = requests.get(url=url,headers=header,timeout=60).content.decode()
    # print(reHtml)
    pattern= re.compile(r'<td(.*?)</td>',re.S)
    result = re.findall(pattern,reHtml)
    if result:  #如果不为空
        resultJson['type'] = result[0].replace('>','')
        reData = result[2]
        pattern = re.compile(r'hash">(.*?)</span>')
        reData = re.findall(pattern,reData)[0]
        if reData != '<span class="glyphicon glyphicon-search text-right">':
            resultJson['data'] = reData
            resultJson['text'] = '破解成功'
        else:
            resultJson['text'] = '破解失败'
    else:
        resultJson['text'] = '破解失败'
    return resultJson
    #result 列表中索引第一个为加密算法，第三个为解密结果,如果解密失败result为空
    # u = 1
    # print(result[2])
    # for i in result:
    #     print(u)
    #     print(i)
    #     u=u+1
    # print(resultJson)

#md5online.org接口解密hash--仅支持32位md5
def hashDecrypt_md5online_org(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'md5online.org'
    url = 'https://www.md5online.org/md5-decrypt.html'
    hashData= {'hash':hash}
    reHtml = requests.post(url=url,data=hashData,headers=header,timeout=60).content.decode()
    pattern = re.compile(r'<span class="result">(.*?)</span>',re.S)
    result = re.findall(pattern,reHtml)
    pattern = re.compile(r'<b>(.*?)</b>')
    result = re.findall(pattern,result[0])
    # print(result)
    if result:
        resultJson['data'] = result[0]
        resultJson['type'] = 'md5'
        resultJson['text'] = '破解成功'
    else:
        resultJson['text'] = '破解失败'
    return resultJson

#md5online.es接口解密hash--仅支持32位md5
def hashDecrypt_md5online_es(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'md5online.es'
    url = 'https://md5online.es/'
    hashData= {'hash':hash}
    reHtml = requests.post(url=url,data=hashData,headers=header,timeout=60).content.decode()
    pattern = re.compile(r"<span class='result'>(.*?)</span>",re.S)
    result = re.findall(pattern,reHtml)
    pattern = re.compile(r'<b>(.*?)</b>')
    result = re.findall(pattern,result[0])
    # print(result)
    if result:
        resultJson['data'] = result[0]
        resultJson['type'] = 'md5'
        resultJson['text'] = '破解成功'
    else:
        resultJson['text'] = '破解失败'
    return resultJson

#md5.my-addr.com接口解密hash--仅支持32位md5
def hashDecrypt_md5_my_addr(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'md5.my-addr.com'
    url = 'http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php'
    hashData= {'md5':hash}
    reHtml = requests.post(url=url,data=hashData,headers=header,timeout=60).content.decode()
    # print(reHtml)
    pattern = re.compile(r"Hashed string</span>:(.*?)</div>",re.S)
    result = re.findall(pattern,reHtml)
    # print(result)
    if result:
        resultJson['data'] = result[0].replace(' ','')
        resultJson['type'] = 'md5'
        resultJson['text'] = '破解成功'
    else:
        resultJson['text'] = '破解失败'
    return resultJson

# md5.ovh接口解密hash--仅支持32位md5
def hashDecrypt_md5_ovh(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'md5.ovh'
    url = 'https://www.md5.ovh/index.php?result=json&md5=' + hash
    reStr =requests.get(url=url,headers=header,timeout=60).content.decode()
    if reStr[0] == 'E':  #表示输入位数错误
        resultJson['text'] = 'md5位数错误'
    elif reStr[0] =='[':
        reJson = json.loads(reStr.replace('[','').replace(']',''))
        resultJson['data'] = reJson['status']
        if reJson['result'] == 'OK':    #表示破解成功
            resultJson['text'] = '破解成功'
            resultJson['type'] = 'md5'
        elif reJson['result'] == 'KO':  #表示破解失败
            resultJson['text'] = '破解失败'
        else:
            resultJson['text'] = '未知错误'
    else:
        resultJson['text'] = '未知错误'

    return resultJson

# tool.chinaz.com接口解密hash--仅支持不超过11位的数字16位md5
def hashDecrypt_tool_chinaz_com(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'tool.chinaz.com'
    url = 'http://tool.chinaz.com/tools/md5.aspx'
    hashData= {'q':hash,'ende':'1','md5type':'0'}
    reHtml=requests.post(url=url,headers=header,data=hashData,timeout=60).content.decode()
    # print(reHtml)
    pattern = re.compile(r'id="MD5Result">(.*?)</textarea>',re.S)
    result = re.findall(pattern,reHtml)
    # print(result)
    if  result:
        if result[0] == '未找到解密结果':
            resultJson['text'] = '破解失败'
        else:
            resultJson['data'] = result[0]
            resultJson['text'] = '破解成功'
            resultJson['type'] = 'md5'
    else:
        resultJson['text'] = '未知错误'
    return resultJson

# ttmd5.com接口解密hash
def hashDecrypt_ttmd5_com(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'ttmd5.com'
    url = 'http://www.ttmd5.com/do.php?c=Decode&m=getMD5&md5=' + hash
    reJson = json.loads(requests.get(url=url,headers=header).content.decode())
    if reJson['flag'] ==1:
        resultJson['data'] = reJson['plain']
        resultJson['text'] = '破解成功'
        resultJson['type'] = reJson['type']
        if reJson['msg']:
            resultJson['text'] = reJson['msg']
        else:
            resultJson['text'] = '破解成功'
    else:
        resultJson['text'] = reJson['msg']
    return resultJson

# pmd5.com接口解密hash
def hashDecrypt_pmd5_com(hash):
    resultJson = {'data': '', 'type': '', 'source': '', 'text': ''}
    resultJson['source'] = 'pmd5.com'
    url = 'https://api.pmd5.com/pmd5api/pmd5?pwd=' + hash
    reJson = json.loads(requests.get(url=url,headers=header).content.decode())
    # print(reJson)
    if reJson['code'] == 0:
        key = list(reJson['result'])[0]
        resultJson['data'] = reJson['result'][key]
        resultJson['type'] = 'md5'
        resultJson['text'] = '破解成功'
    else:
        resultJson['text'] = '破解失败'
    return resultJson









########################################################################################################################


if __name__ == '__main__':
    print('粘贴板内容为：')
    print(pyperclip.paste())    #打印粘贴板内容
    print('是否选择破解粘贴板的值？')
    flag = input('否-请输入0 \n是-请输入回车\n')
    if flag == 0 or flag == '0':
        hash_data = input('输入hash：')
    else:
        hash_data = pyperclip.paste()
    try:
        result = hashDecrypt_somd5_com(hash_data)
        print(result)
        result = hashDecrypt_md5decrypt_net(hash_data)
        print(result)
        result = hashDecrypt_hashtoolkit_com(hash_data)
        print(result)
        result = hashDecrypt_md5online_org(hash_data)
        print(result)
        result = hashDecrypt_md5online_es(hash_data)
        print(result)
        result = hashDecrypt_md5_my_addr(hash_data)
        print(result)
        result = hashDecrypt_md5_ovh(hash_data)
        print(result)
        result = hashDecrypt_tool_chinaz_com(hash_data)
        print(result)
        result = hashDecrypt_ttmd5_com(hash_data)
        print(result)
        result = hashDecrypt_pmd5_com(hash_data)
        print(result)
        # result = hashDecrypt_xmd5_com(hash_data)
        # print(result)
    except:
        print('发生错误（可能原因：开启了系统代理）')

    # 设置休眠时间
    sleepTime = 20
    print('全部查询完毕'+ str(sleepTime) + '秒后关闭')
    time.sleep(sleepTime)
