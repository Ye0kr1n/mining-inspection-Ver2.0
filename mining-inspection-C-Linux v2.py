# -*- coding=utf-8 -*-
import psutil, linecache, ctypes
import os, datetime, time, platform, sys, socket
import requests, hashlib, json, configparser, xlrd, xlwt
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import SubElement
from xml.etree.ElementTree import ElementTree
import uuid

pool_list = []
systemtype = platform.system()
pc_name = socket.gethostname()
pc_ip = socket.gethostbyname(socket.gethostname())
configi = configparser.ConfigParser()
conf_path = r'config-c.ini'


def conn_server(serverip, serverport, token, request_data):
    header = {
        'token': token
    }
    try:
        res = requests.post('http://' + serverip + ':' + serverport, data=request_data, headers=header)
        print("[+]数据已成功发送至服务端")
    except:
        print("[-]发送数据失败，请查看服务器是否配置正常")
    return res


def get_network_connect():
    raddr_list = []
    connlist = psutil.net_connections()
    cache = []
    for i in range(0, len(connlist)):
        if len(connlist[i].raddr) > 0:
            cache.append(connlist[i].raddr[0])
        else:
            continue
    for i in cache:
        if i not in raddr_list:
            raddr_list.append(i)
        else:
            continue
    list(set(raddr_list))
    return raddr_list


def get_network_flow():  # 当前流量特征
    if os == "Windows":
        for interfacePerTcp in c.Win32_PerfRawData_Tcpip_TCPv4():
            sentflow = float(interfacePerTcp.SegmentsSentPersec)  # 已发送的流量
            receivedflow = float(interfacePerTcp.SegmentsReceivedPersec)  # 接收的流量
            per_last_present_flow = sentflow + receivedflow  # 算出1秒后当前的总流量
        present_network_flow = (per_last_present_flow - present_flow) / 1024
    else:
        present_network_flow = all_flow('eth0')

    return "%.2f" % present_network_flow


def check_run_file_hash():  # 检测运行中文件的HASH
    filepath = "NULL"
    # c = wmi.WMI()
    pathinfo = []
    path = []
    localfilehash = []  # 本地文件
    n = 0
    with open("fileHash.list", "r", encoding='gb2312') as f:  # 打开文件
        data = f.read()  # 读取文件
    f.close()
    filelist = json.loads(data)  # Hash特征库
    pids = psutil.pids()
    for process in pids:
        try:
            p = psutil.Process(int(process))
            if p.exe() not in path:
                path.append(p.exe())
            else:
                continue

        except:
            print("%s[-]进程: %s 无法获取目录" % (str(datetime.datetime.now()), p.name()))
    for i in path:
        try:
            with open(i, 'rb') as f:
                sha256obj = hashlib.sha256()
                sha256obj.update(f.read())
                localfilehash.append([i, sha256obj.hexdigest()])
        except:
            print("%s [-]文件:%s 无法获取hash" % (str(datetime.datetime.now()), i))
        f.close()
    for i in filelist:
        for j in localfilehash:
            if filelist[i]['FILEHASH'] == j[1]:
                print("%s [!]查找到文件:%s 挖矿类型为： %s" % (str(datetime.datetime.now()), j[0], filelist[i]['TYPE']))
                filepath = j[0]
                n = 1
                break
    pathinfo.append(localfilehash)
    return {"check_run_file_hash": n, "content": [pathinfo, filepath]}


def net_is_used(port, ip='127.0.0.1'):  # 端口检测

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, port))
        s.shutdown(2)
        print('%s:%d is used' % (ip, port))
        return [True, port]
    except:
        print('%s:%d is unused' % (ip, port))
        return False


def check_free_space_mb():  # C盘剩余量
    statvfs = os.statvfs('/')
    disk_free = round(statvfs.f_frsize * statvfs.f_bfree / 1024 / 1024 / 1024, 2)
    if disk_free < 1:
        n = 1
    else:
        n = 0
    return {"check_free_space_mb": n, "content": disk_free}


def format_flow(flow):
    flow_n = float(flow)
    return (flow_n / 1024)


def all_flow(INTERFACE):
    f = open('/proc/net/dev')
    flow_info = f.readlines()
    in_flow = []
    out_flow = []
    for eth_dev in flow_info:
        if INTERFACE in eth_dev:
            in_flow.append(int(eth_dev.split(':')[1].split()[0]))
            out_flow.append(int(eth_dev.split(':')[1].split()[9]))
    f.close()
    return format_flow(out_flow[0])


def check_port_list():  # 端口检测
    conte = linecache.getlines('port.list')  # 端口在port文件中
    check_list = []
    for i in range(len(conte)):  # 病毒一般占用4位数端口，端口范围可选，或针对端口关闭
        if net_is_used(int(conte[i])):
            n = 1
            check_list.append(conte[i].replace('\n', ''))
        else:
            n = 0
            check_list.append("NULL")
    return {"check_port_list": n, "content": check_list}


def check_memcpu():  # 获取内存以及CPU数据
    global n
    data = psutil.virtual_memory()
    total = data.total  # 总内存,单位为byte
    free = data.available  # 可以内存
    memory = "%d" % (int(round(data.percent))) + "%"  # 内存使用率
    cpu = "%0.2f" % psutil.cpu_percent(interval=1) + "%"  # CPU使用率
    if int(round(data.percent)) > 75 and psutil.cpu_percent(interval=1) > 75:  # 挖矿一个特征
        n = 1  # ☆☆☆阈值
    else:
        n = 0
    return {"checkMemCpu": n, "content": [cpu, memory]}


def check_flow():  # 带宽检测
    flow = get_network_flow()
    if float(flow) > 3000:  # 病毒一般占用3033KB/s 阈值
        n = 1
    else:
        n = 0
    return {"check_flow": n, 'content': flow}  # KB/s


def process_check():  # 进程检测
    processchecklist = []
    n = 0
    pids = psutil.pids()
    cont = linecache.getlines('process.list')  # 读入进程列表
    for j in range(len(cont)):
        cont[j] = cont[j][:len(cont[j]) - 1]
    for pid in pids:
        try:
            p = psutil.Process(pid)
            if p.name() not in processchecklist:
                processchecklist.append(p.name())
            else:
                continue
        except:
            print("[-]%s pid:%s 获取名称失败，可尝试重新运行该程序" % (str(datetime.datetime.now()), str(pid)))
        # print(p.name())
        for j in range(len(cont)):
            if p.name() == cont[j]:
                n = 1
    return {"process_check": n, "content": processchecklist}


def pool_conn_check():  # 外联ip黑名单检测
    connect = get_network_connect()
    get_pool_list = linecache.getlines('PoolList.list')
    n = 0
    for i in connect:
        if '#' in i:
            continue
        if i in get_pool_list:
            n = 1

        else:
            continue
    return {"pool_connect_check": n, "content": connect}


def update_pool_list():
    pool_list1 = []
    pool_list2 = []
    new_pool_list = []
    r = requests.get(url='https://reputation.alienvault.com/reputation.data', timeout=100)
    with open("./cache/reputation.data", "wb+") as code:
        code.write(r.content)
    r = requests.get(url='https://myip.ms/files/blacklist/general/latest_blacklist.txt', timeout=100)
    with open("./cache/latest_blacklist.txt", "wb+") as code:
        code.write(r.content)
    pool_list_one = linecache.getlines('./cache/reputation.data')
    for i in pool_list_one:
        pool_list1.append(i.split('#')[0])
    pool_list_two = linecache.getlines('./cache/latest_blacklist.txt')
    for i in range(13, len(pool_list_two)):
        pool_list2.append(pool_list_two[i].split('\t\t\t #')[0])
    for i in pool_list1:
        if i not in new_pool_list:
            new_pool_list.append(i)
        else:
            continue
    for i in pool_list2:
        if i not in new_pool_list:
            new_pool_list.append(i)
        else:
            continue
    f = open("./PoolList.list", "w+")
    f.write("#UpdateTime:%s" % str(datetime.datetime.now()))
    for i in new_pool_list:
        f.write(i + '\r')
    f.close()
    code.close()
    try:
        code.close()
        os.remove('./cache/latest_blacklist.txt')
        os.remove('./cache/reputation.data')
    except:
        print("[-]缓存文件移除失败，如有需要请手动删除./cache/目录下的文件")


def banner():
    print("  __  __ _       _                _____                 _   _                    ___  ")
    print(" |  \/  (_)     (_)              / ____|               | | (_)                  |__ \ ")
    print(" | \  / |_ _ __  _ _ __   __ _  | (___  _ __   ___  ___| |_ _  ___  _ __   __   __ ) |")
    print(" | |\/| | | '_ \| | '_ \ / _` |  \___ \| '_ \ / _ \/ __| __| |/ _ \| '_ \  \ \ / // / ")
    print(" | |  | | | | | | | | | | (_| |  ____) | |_) |  __/ (__| |_| | (_) | | | |  \ V // /_ ")
    print(" |_|  |_|_|_| |_|_|_| |_|\__, | |_____/| .__/ \___|\___|\__|_|\___/|_| |_|   \_/|____|")
    print("                          __/ |        | |                                            ")
    print("                         |___/         |_|                                            ")
    print("\t\t\t\t\tMining Spection v2")
    print("\t\t\t\t\tPowered by Ye0kr1n")
    print("\t\t\t\t\t2022-3-6")


def checklist():  # 主检测模块
    check_ans = {}
    ans = []
    n = 0
    checkcm = check_memcpu()  # return {"checkMemCpu": n, "content": [cpu,memory]}
    print("系统类型为:%s" % os)
    check_ans['systemtype'] = systemtype
    check_ans['pc_name'] = pc_name
    check_ans['pc_ip'] = pc_ip
    check_ans['CPU'] = checkcm['content'][0]
    check_ans['Memory'] = checkcm['content'][1]
    if checkcm['checkMemCpu'] == 0:
        print("%s[+]CPU以及内存检测通过" % str(datetime.datetime.now()))
    else:
        print("%s[!]CPU以及内存检测不通过" % str(datetime.datetime.now()))
        ans.append('CPU')
        ans.append('Memory')
        n = 1
    checkfree = check_free_space_mb()  # "check_free_space_mb": n, "content": disk_free
    check_ans['Disk'] = checkfree['content']
    if checkfree['check_free_space_mb'] == 0:
        print("%s[+]磁盘检测通过" % str(datetime.datetime.now()))
    else:
        print("%s[!]磁盘检测不通过" % str(datetime.datetime.now()))
        n = 1
        ans.append('Disk')
    processc = process_check()  # "process_check": n, "content": processchecklist
    check_ans['Process'] = processc['content']
    if processc['process_check'] == 0:
        print("%s[+]进程检测通过" % str(datetime.datetime.now()))
    else:
        print("%s[!]进程检测不通过" % str(datetime.datetime.now()))
        n = 1
        ans.append('Process')
    checkport = check_port_list()  # "check_port_list": n, "content":check_list
    check_ans['Port'] = checkport['content']
    if checkport['check_port_list'] == 0:
        print("%s[+]开放端口检测通过" % str(datetime.datetime.now()))
    else:
        print("%s[!]开放端口检测不通过" % str(datetime.datetime.now()))
        n = 1
        ans.append('Port')
    process_hash = check_run_file_hash()  # "check_run_file_hash": n, "content": pathinfo
    check_ans['process_hash'] = process_hash['content']
    if process_hash['check_run_file_hash'] == 0:
        print("%s[+]进程HASH检测通过" % str(datetime.datetime.now()))
    else:
        print("%s[!]进程HASH检测不通过" % str(datetime.datetime.now()))
        n = 1
        ans.append('process_hash')
    flow = check_flow()  # "check_flow": n, 'content':flow
    check_ans['flow'] = flow['content'] + 'KB/s'
    if flow['check_flow'] == 0:
        print("%s[+]带宽占用检测通过" % str(datetime.datetime.now()))
    else:
        print("%s[!]带宽占用检测不通过" % str(datetime.datetime.now()))
        n = 1
        ans.append('flow')
    polconn = pool_conn_check()  # {"pool_connect_check": n, "content": connect}
    check_ans['NetWorkConnect'] = polconn['content']
    if polconn['pool_connect_check'] == 0:
        print("%s[+]外联检测通过" % str(datetime.datetime.now()))
    else:
        print("%s[!]外联检测不通过" % str(datetime.datetime.now()))
        n = 1
        ans.append('NetWorkConnect')
    print("%s[+]所有项目检查完成" % str(datetime.datetime.now()))
    return [check_ans, ans, n]


# def report(modes):
# if modes == 'host':
# print("%s[+]当前模式为单主机模式" % str(datetime.datetime.now()))

# elif modes == 'net':
#  print("%s[+]当前模式为网络模式" % str(datetime.datetime.now()))

# elif modes == 'offline':
# print("%s[+]当前模式为离线核查模式" % str(datetime.datetime.now()))


def e2chinese(en):
    name = {
        'CPU': 'CPU',
        'Memory': '内存',
        'Disk': '磁盘',
        'Process': '进程',
        'Port': '端口',
        'process_hash': '进程对应HASH',
        'flow': '带宽占用',
        'NetWorkConnect': '网络外联'
    }
    return name[en]


def mode_onlinecheck():
    check_ans = checklist()
    print("[+]单主机检查已完成")
    print("[+]检查信息如下:")
    print("系统类型:%s" % check_ans[0]['systemtype'])
    print("CPU:%s" % check_ans[0]['CPU'])
    print("内存占用:%s" % check_ans[0]['Memory'])
    print("磁盘占用:%s" % check_ans[0]['Disk'])
    print("本地运行中进程信息:")
    for i in check_ans[0]['Process']:
        print("\t" + i)
    print("异常端口信息:%s" % check_ans[0]['Port'])
    print("进程对应HASH信息:")
    for i in check_ans[0]['process_hash'][0][0]:
        print("\t[+]进程名对应路径:%s 对应hash:%s" % (i[0], i[1]))
    if not isinstance(check_ans[0]['process_hash'][1], str):
        print("\t[!]发现异常进程:%s" % check_ans[0]['process_hash'][1])
    print("带宽占用信息:%s" % check_ans[0]['flow'])
    print("本机网络外联信息:")
    for i in check_ans[0]['NetWorkConnect']:
        print(i)
    if len(check_ans[1]) == 0:
        print("[+]该主机不存在异常信息")
    else:
        print("[-]该主机存在异常信息,异常信息如下:")
        for i in check_ans[1]:
            print("\t[-]%s存在异常" % e2chinese(i))
    if check_ans[2] == 1:
        print("[!]该主机存在异常信息，请细察")
    else:
        print("[+]该主机不存在异常信息，检查通过!")
    return check_ans


def mode_import_xml(path):
    print("离线核查模式启动")
    path_list = os.listdir(path)
    path_list.remove('.DS_Store')
    print(path_list)

def mode_offlinecheck():
    check_ans = checklist()
    print("[+]单主机检查已完成")
    print("[+]检查信息如下:")
    print("系统类型:%s" % systemtype)
    print("CPU:%s" % check_ans[0]['CPU'])
    print("内存占用:%s" % check_ans[0]['Memory'])
    print("磁盘占用:%s" % check_ans[0]['Disk'])
    print("本地运行中进程信息:")
    for i in check_ans[0]['Process']:
        print("\t" + i)
    print("异常端口信息:%s" % check_ans[0]['Port'])
    print("进程对应HASH信息:")
    for i in check_ans[0]['process_hash'][0][0]:
        print("\t[+]进程名对应路径:%s 对应hash:%s" % (i[0], i[1]))
    if not len(check_ans[0]['process_hash'][1]) == 4:
        print("\t[!]发现异常进程:%s" % check_ans[0]['process_hash'][1])
    print("带宽占用信息:%s" % check_ans[0]['flow'])
    print("本机网络外联信息:")
    for i in check_ans[0]['NetWorkConnect']:
        print(i)
    if len(check_ans[1]) == 0:
        print("[+]该主机不存在异常信息")
    else:
        print("[-]该主机存在异常信息,异常信息如下:")
        for i in check_ans[1]:
            print("\t[-]%s存在异常" % e2chinese(i))
    if check_ans[2] == 1:
        print("[!]该主机存在异常信息，请细察")
    else:
        print("[+]该主机不存在异常信息，检查通过!")
    while (1):
        ins = input("请选择导出报告模板:\r\n 1、单主机检测报告 2、离线核查模式xml报告\r\n请输入:")
        if ins == "2":
            print_xml(check_ans)
            print("[+]xml文件已导出,欢迎使用本工具,再会\r\nPowered by Ye0kr1n")
            break
        elif ins == "1":
            print_xls(check_ans)
            print('')
            break
        else:
            print("[X]输入异常请重新输入")


def print_xls(data):
    flag = ''
    book = xlwt.Workbook()
    writetext = ['主机名', 'IP地址', '系统类型', 'CPU', '内存', '异常端口', '带宽占用', '系统盘剩余', '本地运行中进程名称', '本地运行中进程路径', '本地运行中进程HASH',
                 '外连IP', '异常项']
    sheet = book.add_sheet(pc_ip + '_' + pc_name)
    for i in range(0, len(writetext)):
        sheet.write(i, 0, writetext[i])
    sheet.write(0, 1, pc_name)
    sheet.write(1, 1, pc_ip)
    sheet.write(2, 1, systemtype)
    sheet.write(3, 1, data[0]['CPU'])
    sheet.write(4, 1, data[0]['Memory'])
    sheet.write(5, 1, data[0]['Port'])
    sheet.write(6, 1, str(data[0]['flow']))
    sheet.write(7, 1, str(data[0]['Disk']) + 'GB')
    for i in range(1, len(data[0]['Process'])):
        sheet.write(8, i, data[0]['Process'][i - 1])
    for i in range(1, len(data[0]['process_hash'][0][0])):
        sheet.write(9, i, data[0]['process_hash'][0][0][i - 1][0])
        sheet.write(10, i, data[0]['process_hash'][0][0][i - 1][1])
    for i in range(1, len(data[0]['NetWorkConnect'])):
        sheet.write(11, i, data[0]['NetWorkConnect'][i - 1])
    if len(data[1]) == 0:
        sheet.write(12, 1, "该主机不存在异常项")
    else:
        flag = 'except'
        # print(data[1])
        x = 1
        for i in data[1]:
            e2c = e2chinese(i)
            sheet.write(12, x, e2c)
            x = x + 1
    report_path = configi['client_config']['report_path']
    try:
        file_name = report_path + '/xls/check_report_' + pc_name + '_' + '_' + pc_ip + '_' + str(
            uuid.uuid4()) + '_' + flag + '.xls'
        book.save(file_name)
        print("[+]文件已导出,欢迎使用本工具,再会\r\nPowered by Ye0kr1n")
    except:
        print("[!]单主机检查报告保存失败，请尝试重新运行本程序")


def print_xml(data):
    root = Element('root')
    head = SubElement(root, 'head')
    pname = SubElement(head, 'pcname')
    pname.text = data[0]['pc_name']
    pcip = SubElement(head, 'pc_ip')
    pcip.text = data[0]['pc_ip']
    ostype = SubElement(head, 'systemtype')
    ostype.text = systemtype
    nowtime = SubElement(head, "check_time")
    nowtime.text = str(datetime.datetime.now())
    check_list = SubElement(root, 'check_list')
    cpu = SubElement(check_list, 'cpu')
    cpu.text = data[0]['CPU']
    memo = SubElement(check_list, 'Memory')
    memo.text = data[0]['Memory']
    disk = SubElement(check_list, 'Disk_Free')
    disk.text = str(float(data[0]['Disk'])) + 'GB'
    proc = SubElement(check_list, 'Process')
    proc.text = str(data[0]['Process'])
    port = SubElement(check_list, 'Port')
    port.text = str(data[0]['Port'])
    proc_hash = SubElement(check_list, 'Process_HASH')
    proc_hash.text = str(data[0]['process_hash'][0][0])
    open_port = SubElement(check_list, 'port_check')
    PortList = []
    for i in data[0]['Port']:
        PortList.append(i.replace('\\n', ''))
    open_port.text = str(PortList)
    flow = SubElement(check_list, 'flow')
    flow.text = str(data[0]['flow'])
    connect = SubElement(check_list, 'NetworkConnect')
    connect.text = (str(data[0]['NetWorkConnect']))
    tree = ElementTree(root)
    configi.read(conf_path, encoding="utf8")
    report_path = configi['client_config']['report_path']
    filename = report_path + '/xml/result_' + pc_ip + "_" + pc_name + '_' + str(uuid.uuid4()) + '_outlinecheck.xml'
    try:
        tree.write(filename, encoding='utf-8')
        print("[+]离线文件成功导出,详细路径:%s" % filename)
    except:
        print("[!]单主机XML保存失败,请尝试重新运行本程序")


def main():  # 主函数
    banner()
    # ans = []
    configi.read(conf_path, encoding="utf8")
    server_ip = configi['server_config']['server_ip']
    server_port = configi['server_config']['serverport']
    server_token = configi['server_config']['token']
    write_path = configi['client_config']['report_path']
    print("欢迎使用挖矿专项检测工具 V2.0")
    print("温馨提示:请在使用前检查ini配置文件是否正常")
    print("请先选择检测模式：\r\n1、本地模式\r\n2、服务端模式\r\n3、离线核查模式\r\n4、更新矿池列表信息\r\n")
    while True:
        mode = input("请输入模式:")
        if mode == "1":
            print("本地模式启动")
            mode_offlinecheck()
            break
        if mode == "2":
            print("服务端模式启动")
            print("[+]服务器IP:%s \r\n 服务器端口:%s \r\n" % (server_ip, server_port))
            requdata = mode_onlinecheck()
            conn_server(server_ip, server_port, "asasasas", str(requdata))
            break
        if mode == "3":
            print("离线核查模式启动")
            mode_import_xml(configi['client_config']['report_path'])
            break
        if mode == "4":
            update_pool_list()
            break
        if not (mode == "1") and not (mode == "2") and not (mode == "3") and not (mode == "4"):
            print("输入有误请重新输入\r\n")
    # ans = checklist()
    # print(ans)


if __name__ == '__main__':
    main()
