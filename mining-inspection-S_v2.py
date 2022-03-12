import datetime
import socket, re, configparser
import uuid
#from multiprocessing import Process
import multiprocessing
import ast, xlwt
configi = configparser.ConfigParser()
conf_path = r'config-s.ini'
configi.read(conf_path, encoding="utf8")


def e2chinese(en):
    name = {
        'CPU': 'CPU',
        'Memory': '内存',
        'Disk': '磁盘',
        'Process': '进程',
        'Port': '端口',
        'process_hash': '进程对应HASH',
        'flow': '带宽占用',
        'NetWorkConnect': '网络外连',
        'GPU':'GPU'
    }
    return name[en]


def processing_report(datas):
    pr_path = configi['server_config']['reportlocation']
    data = ast.literal_eval(datas)
    book = xlwt.Workbook()
    writetext = ['主机名', 'IP地址', '系统类型', 'CPU','GPU', '内存', '异常端口', '带宽占用', '系统盘剩余', '本地运行中进程名称', '本地运行中进程路径','本地运行中进程HASH', '外连IP', '异常项']
    try:
        sheet = book.add_sheet(data[0]['pc_name'] + '_' + data[0]['pc_ip'])
    except:
        sheet = book.add_sheet(data[0]['pc_name'] + '_' + data[0]['pc_ip'] + "(1)")
    for i in range(0, len(writetext)):
        sheet.write(i, 0, writetext[i])
    sheet.write(0, 1, data[0]['pc_name'])
    sheet.write(1, 1, data[0]['pc_ip'])
    sheet.write(2, 1, data[0]['systemtype'])
    sheet.write(3, 1, data[0]['CPU'])
    sheet.write(4, 1, str(data[0]['GPU'][0][0])+'%')
    sheet.write(5, 1, data[0]['Memory'])
    sheet.write(6, 1, data[0]['Port'])
    sheet.write(7, 1, str(data[0]['flow']))
    sheet.write(8, 1, str(data[0]['Disk']) + 'GB')
    for i in range(1, len(data[0]['Process'])):
        sheet.write(9, i, data[0]['Process'][i - 1])
    for i in range(1, len(data[0]['process_hash'][0][0])):
        sheet.write(10, i, data[0]['process_hash'][0][0][i - 1][0].replace('\\\\','\\'))
        sheet.write(11, i, data[0]['process_hash'][0][0][i - 1][1])
    for i in range(1, len(data[0]['NetWorkConnect'])):
        sheet.write(12, i, data[0]['NetWorkConnect'][i - 1])
    if len(data[1]) == 0:
        sheet.write(13, 1, "该主机不存在异常项")
        flag = "Success"
    else:
        # print(data[1])
        x = 1
        flag="except"
        for i in data[1]:
            e2c = e2chinese(i)
            sheet.write(13, x, e2c)
            x = x + 1
    try:
        filename = pr_path + '/xls/Write_check_server_report_' + data[0]['pc_name'] + '_' + data[0][
            'pc_ip'] + '_' + str(uuid.uuid4()) + '_' + flag + '.xls'
        book.save(filename)
        print("[+]主机ip:%s 检查报告已保存成功" % data[0]['pc_ip'])
        prin_logs("[+]主机ip:%s 检查报告已保存成功,报告存储位置:%s" % (data[0]['pc_ip'], filename))
        print("[+]报告存储位置:%s" % filename)
    except:
        print("[!]检查报告保存失败，请尝试重新运行本程序")
        prin_logs("[!]ip:%s检查报告保存失败,请尝试重新运行" % data[0]['pc_ip'])


def prin_logs(data):
    path = configi['server_config']['log_path']
    filename = str(datetime.datetime.now().year) + str(datetime.datetime.now().month) + str(
        datetime.datetime.now().day) + "_serverlog.log"
    f = open(path + '/' + filename, 'a', encoding="utf-8")
    f.write(str(datetime.datetime.now()) + '\t' + data + '\n')
    f.close()


def process_requ(data):
    body = str(data).replace('\\r\\n', '\r\n')
    # print("processdata:", body.replace('\\r\\n', '\r\n'))
    datas = body.splitlines()[-1].replace('\"', '')
    # print(datas)
    prin_logs("recv datas:" + datas)
    processing_report(datas)


def handle_client(client_socket):
    request_data = client_socket.recv(65535)
    # print("request data:", request_data)
    #process_requ(request_data)
    # 构造响应数据
    try:
        process_requ(request_data)
        response_start_line = res_body('OK')[0]
        response_headers = res_body('OK')[1]
        response_body = res_body('OK')[2]
    except:
    #filename = reqdata(request_data)
        response_start_line = res_body('hello')[0]
        response_headers = res_body('hello')[1]
        response_body = res_body('hello')[2]
    response = response_start_line + response_headers + "\r\n" + response_body
    # 向客户端返回响应数据
    client_socket.send(bytes(response, "utf-8"))
    # 关闭客户端连接
    client_socket.close()


def banner():
    print("  __  __ _       _                _____                 _   _                    ___  ")
    print(" |  \/  (_)     (_)              / ____|               | | (_)                  |__ \ ")
    print(" | \  / |_ _ __  _ _ __   __ _  | (___  _ __   ___  ___| |_ _  ___  _ __   __   __ ) |")
    print(" | |\/| | | '_ \| | '_ \ / _` |  \___ \| '_ \ / _ \/ __| __| |/ _ \| '_ \  \ \ / // / ")
    print(" | |  | | | | | | | | | | (_| |  ____) | |_) |  __/ (__| |_| | (_) | | | |  \ V // /_ ")
    print(" |_|  |_|_|_| |_|_|_| |_|\__, | |_____/| .__/ \___|\___|\__|_|\___/|_| |_|   \_/|____|")
    print("                          __/ |        | |                                            ")
    print("                         |___/         |_|                                            ")
    print("\t\t\t\t\tMining Spection v2 Server")
    print("\t\t\t\t\tPowered by Ye0kr1n")
    print("\t\t\t\t\t2022-3-10")
    print("温馨提示:请在使用前检查ini配置文件是否正常")


def res_body(type):
    response_text = {
        'OK': ["HTTP/1.1 200 OK\r\n",
               "Server: Nsfocus-Ye0kr1n-report-manipulate-server\r\nsetContentType:text/html;charset=utf-8\r\n",
               "OK Report receiving completed"],
        'token_error': ["HTTP/1.1 403 Error\r\n",
                        "Server: Nsfocus-Ye0kr1n-report-manipulate-server\r\nsetContentType:text/html;charset=utf-8\r\n",
                        "TokenError"],
        'exception': ["HTTP/1.1 500 Error\r\n",
                      "Server: Nsfocus-Ye0kr1n-report-manipulate-server\r\nsetContentType:text/html;charset=utf-8\r\n",
                      "Data exception"],
        'hello': ["HTTP/1.1 200 OK\r\n",
                  "Server: Nsfocus-Ye0kr1n-report-manipulate-server\r\nsetContentType:text/html;charset=utf-8\r\n",
                  "<h1>Server Test</h1>\r\n<h2>Report server running test</h2>\r\n<hr>\r\n<h3>Powered by:Nsfocus Ye0kr1n <br> date:%s</h3>" % str(
                      datetime.datetime.now())]
    }
    return response_text[type]


def reqdata(data):
    request_lines = data.splitlines()
    request_start_line = request_lines[0]
    file_name = re.match(r"\w+ +(/[^ ]*) ", request_start_line.decode("utf-8")).group(1)
    return file_name


if __name__ == "__main__":
    banner()
    port = int(configi['server_config']['port'])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("", port))
    print('[+]本地监听端口:%s'%str(port))
    server_socket.listen(128)

    while True:
        client_socket, client_address = server_socket.accept()
        print("[+]有用户连接上了,ip地址:%s    端口:%s" % (client_address[0], client_address[1]))
        prin_logs("有用户连接上了,ip地址:%s    端口:%s" % (client_address[0], client_address[1]))
        handle_client_process = multiprocessing.Process(target=handle_client, args=(client_socket,))
        handle_client_process.start()
        client_socket.close()
