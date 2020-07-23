# 全连接扫描
from socket import *
from PyQt5 import QtGui
import threading

lock = threading.Lock()
threads = []
all_open_port = ''

def portScanner(host,port):
    global all_open_port

    try:
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((host,port))
        lock.acquire()
        all_open_port += str(port)+' '
        lock.release()
        s.close()
    except:
        pass



def main(i,ip_num,ip,port,par,table,model): # i表示此时是第几组IP，ip_num表示一共有多少组IP
    setdefaulttimeout(1)
    global all_open_port
    print(all_open_port)
    port_num = len(port)
    step = port_num*(i-1)

    for j in range(port_num):

        t = threading.Thread(target=portScanner, args=(ip, port[j]))
        threads.append(t)
        t.start()
        step += 1
        if step==ip_num*port_num:
            par.setValue(100)
        else:
            par.setValue(100*step/(ip_num*port_num*1.0))


    for t in threads:
        t.join()


    if all_open_port=="":
        model.appendRow([QtGui.QStandardItem(ip),QtGui.QStandardItem("no open port")])
    else:
        model.appendRow([QtGui.QStandardItem(ip),QtGui.QStandardItem(all_open_port)])

    all_open_port = ""

