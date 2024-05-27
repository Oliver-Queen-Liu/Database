# 相当于天线，默认目标地址为192.168.49.160，端口号为 8080
# 下行报文指上位机发送给接收机
import tkinter as tk
from threading import Thread
import socket


class ReceiveApp:
    def __init__(self, window):
        self.window = window
        self.window.title("模拟上位机，发送下行报文，接收上行报文")

        # 接收区域
        self.recv_frame = tk.Frame(window)
        self.recv_frame.pack(padx=10, pady=10)

        self.recv_label = tk.Label(self.recv_frame, text="接收数据")
        self.recv_label.pack()

        self.recv_text = tk.Text(self.recv_frame, height=15, width=50)
        self.recv_text.pack()

        # 发送区域
        self.send_frame = tk.Frame(window)
        self.send_frame.pack(padx=10, pady=10)

        self.style_label = tk.Label(self.send_frame, text="指令类型:")
        self.style_label.pack(side=tk.LEFT)

        self.style_entry = tk.Entry(self.send_frame)
        self.style_entry.pack(side=tk.LEFT)

        self.content_label = tk.Label(self.send_frame, text="指令内容:")
        self.content_label.pack(side=tk.LEFT)

        self.content_entry = tk.Entry(self.send_frame)
        self.content_entry.pack(side=tk.LEFT)

        # 获取完整指令
        self.all_msg = tk.Label(self.send_frame, text="完整指令:")
        self.all_msg.pack(side=tk.LEFT)

        self.all_msg = tk.Entry(self.send_frame)
        self.all_msg.pack(side=tk.LEFT)

        self.send_button = tk.Button(self.send_frame, text="发送", command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        self.sk = socket.socket(type=socket.SOCK_DGRAM)
        self.sk.bind(("127.0.0.1", 8080))

        # 开始接收数据的线程
        self.thread = Thread(target=self.receive_data)
        self.thread.daemon = True
        self.thread.start()

    # 下行报文18字节固定长度
    """帧格式：
        0~3     帧头    BYTE[4]    4         固定为0x58443341
        4       指令类型 UINT8      1         0x00:开始停止       0x01:工况查询       0x02:设备重置    0x03:授时指令      0x04:频率设置   
                                            0x05:本机地址设置   0x06:本机位置设置     0x07:开启关闭测试模式
        5~14    指令内容 BYTE[10]   10       根据指令类型填充，当指令类型为0x01、0x02时可不填充
        15~17   帧尾    BYTE[3]     3       固定为0x334441
    """

    def send_message(self):
        # 1.创建udp对象
        style = self.style_entry.get()
        print(style)
        content = self.content_entry.get()
        print(content)
        if style != "" or content != "":
            head = "58443341"
            tail = "334441"
            msg = head + style + content + tail
        else:
            all_message = self.all_msg.get()
            msg = all_message.split(" ")
            msg = "".join(msg)
            print(msg)
        # sendto( 二进制字节流，ip端口号 )
        self.sk.sendto(msg.encode(), ("127.0.0.1", 5010))

    def receive_data(self):
        while True:
            msg, addr = self.sk.recvfrom(1024)
            message_to_display = "Received: " + msg.decode() + " from " + str(addr)
            self.recv_text.insert(tk.END, message_to_display + "\n")
            self.analysis_message(msg)
            # 上行报文采用不定长帧
            """帧格式：
            0~3 帧头  BYTE[4] 4 固定为0x58443341

            4~7  流水号  UINT32 4 0x00000000~0xFFFFFFFF循环，用于判断帧连续

            8~13 时标（年月日时分秒） BYTE[6] 6 若报文类别为0x01、0x02、0x03，此时间为FPGA采到第一bit数据时间或者第一个脉冲的起始时间；若报文类别为0xFF，此时间为组包时的时间

            14~17 时标（秒内计数器） UINT32 4

            18 报文类型 BYTE 1  0x01：AIS通道1信息；0x02：AIS通道2信息；0x03：ACARS通道1信息；0x04：ACARS通道2信息；0x05：ACARS通道3信息；0x06：ACARS通道4信息；0x07：ADS-B信息；0x08：IFF信息；0xFF：工况。19~20数据长度UINT16 2指数据段的长度，不包括帧头、帧尾和其它字段。

            21~20+n 数据段 BYTE[n] n 根据报文类型区分

            21+n~23+n 帧尾 BYTE[3] 3 固定为0x334441
            """

    # 解析下行报文
    def analysis_message(self, msg):
        global water
        getmessage = msg.decode()

        # 如果帧头不是0x58443341，则报文错误
        if getmessage[0:8] != "58443341":
            first_type = "错误类型:帧头错误"
            self.recv_text.insert(tk.END, first_type + "\n")
            return
        else:
            first_type = "帧头正常"
            self.recv_text.insert(tk.END, first_type + "\n")

        # 判断是否连续
        Water = '{:08X}'.format(water)
        water = water + 1
        if getmessage[8:16] == Water:
            k = "帧连续"
            self.recv_text.insert(tk.END, k + "\n")
        else:
            k = "帧不连续，有漏帧"
            self.recv_text.insert(tk.END, k + "\n")

        # 汇报时间
        """
                授时指令内容：
                0    年    UINT8    1       00-99，对应0x00-0x63,基数为2000，例如：2001年对应0x01,2099年对应0x63。
                1    月    UINT8    1       01-12，对应0x01-0x0C
                2    日    UINT8    1       01-31，对应0x01-0x1F
                3    时    UINT8    1       00-23，对应0x00-0x17
                4    分    UINT8    1       00-59，对应0x00-0x3B
                5    秒    UINT8    1       00-59，对应0x00-0x3B
                6-9    保留    UINT8    4 
            """
        year = int(getmessage[16:18], 16) + 2000
        month = int(getmessage[18:20], 16)
        day = int(getmessage[20:22], 16)
        hour = int(getmessage[22:24], 16)
        minute = int(getmessage[24:26], 16)
        second = int(getmessage[26:28], 16)
        self.recv_text.insert(tk.END, "当前时间为: " + str(year) + "年" + str(month) + "月" + str(day) + "日" + str(
            hour) + "时" + str(minute) + "分" + str(second) + "秒\n")

        # 秒内计数器
        one = int(getmessage[28:30], 16)
        two = int(getmessage[30:32], 16)
        three = int(getmessage[32:34], 16)
        four = int(getmessage[34:36], 16)
        self.recv_text.insert(tk.END,
                              "秒内计数器: " + str(one) + "." + str(two) + "." + str(three) + "." + str(four) + "\n")

        # 报文类型
        if getmessage[36:38] == "01":
            k = "AIS通道1信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "02":
            k = "AIS通道2信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "03":
            k = "ACARS通道1信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "04":
            k = "ACARS通道2信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "05":
            k = "ACARS通道3信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "06":
            k = "ACARS通道4信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "07":
            k = "ADS-B信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "08":
            k = "IFF信息"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        elif getmessage[36:38] == "FF":
            k = "工况"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")
        else:
            k = "错误"
            self.recv_text.insert(tk.END, "报文类型:" + k + "\n")

        # 数据长度
        self.recv_text.insert(tk.END, "数据长度：" + getmessage[38:42] + "\n")

        #AIS信息
        if getmessage[36:38] == "01" or getmessage[36:38] == "02":
            if getmessage[42:44] == "01" or getmessage[42:44] == "02" or getmessage[42:44] == "03":
                ship_style = "A类船位置报告消息"
                self.recv_text.insert(tk.END, "消息ID：" + ship_style + "\n")
            elif getmessage[42:44] == "05":
                ship_style = "A类船的静态消息"
                self.recv_text.insert(tk.END, "消息ID：" + ship_style + "\n")
            elif getmessage[42:44] == "12":
                ship_style = "B类船位置报告消息"
                self.recv_text.insert(tk.END, "消息ID：" + ship_style + "\n")
            elif getmessage[42:44] == "24":
                ship_style = "B类船的静态消息"
                self.recv_text.insert(tk.END, "消息ID：" + ship_style + "\n")
            else:
                ship_style = "错误"
                self.recv_text.insert(tk.END, "消息ID：" + ship_style + "\n")

            #用户ID
            self.recv_text.insert(tk.END, "用户ID：" + getmessage[44:54] + "\n")

            #IMO编号
            self.recv_text.insert(tk.END, "IMO编号：" + getmessage[54:62] + "\n")

            #呼号
            self.recv_text.insert(tk.END, "呼号：" + getmessage[62:76] + "\n")

            #船名
            self.recv_text.insert(tk.END, "船名：" + getmessage[76:116] + "\n")

            #船舶和货物类型
            if getmessage[116:118] == "00":
                jobs = "捕捞"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "01":
                jobs = "拖船"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "02":
                jobs = "拖船且推带长度超过200米或宽度超过25米"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "03":
                jobs = "从事挖掘或水下作业"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "04":
                jobs = "从事潜水作业"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "05":
                jobs = "从事军事行动"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "06":
                jobs = "帆船"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "07":
                jobs = "游艇"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "21":
                jobs = "运载DG、HS或者MP、IMO危险品或X（2）类污染物"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "32":
                jobs = "运载DG、HS或者MP、IMO危险品或Y（2）类污染物"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "43":
                jobs = "运载DG、HS或者MP、IMO危险品或Z（2）类污染物"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "50":
                jobs = "引航船舶"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "51":
                jobs = "搜救船舶"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "52":
                jobs = "拖轮"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "53":
                jobs = "港口补给船"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "54":
                jobs = "安装有防污染设施或设备的船舶"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "55":
                jobs = "执法船舶"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "58":
                jobs = "医疗运输船舶"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "59":
                jobs = "非武装冲突参与国的船舶和航空器"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "60":
                jobs = "客轮"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "70":
                jobs = "货轮"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            elif getmessage[116:118] == "80":
                jobs = "油轮"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")
            else:
                jobs = "错误"
                self.recv_text.insert(tk.END, "船舶和货物类型：" + jobs + "\n")


            # 船舶宽度
            self.recv_text.insert(tk.END, "船舶宽度：" + getmessage[118:122] + "\n")

            # 船舶长度
            self.recv_text.insert(tk.END, "船舶长度：" + getmessage[122:126] + "\n")

            #预计到达时间
            month = int(getmessage[126:128], 16)
            day = int(getmessage[128:130], 16)
            hour = int(getmessage[130:132], 16)
            minute = int(getmessage[132:134], 16)
            self.recv_text.insert(tk.END, "预计到达时间为: " + str(month) + "月" + str(day) + "日" + str(
                hour) + "时" + str(minute) + "分" "\n")

            #目前最大静态吃水
            depth = int(getmessage[134:136],16)
            depth = depth / 10
            self.recv_text.insert(tk.END, "目前最大静态吃水：" + str(depth) + "米\n")

            #目的地
            self.recv_text.insert(tk.END, "目的地：" + getmessage[136:176] + "\n")

            #导航状态
            if  getmessage[176:178] == "00":
                navigation_status = "发动机使用中"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "01":
                navigation_status = "锚泊"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "02":
                navigation_status = "未操纵"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "03":
                navigation_status = "有限适航性"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "04":
                navigation_status = "受船舶吃水限制"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "05":
                navigation_status = "系泊"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "06":
                navigation_status = "搁浅"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "07":
                navigation_status = "从事捕捞"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "08":
                navigation_status = "航行中"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            elif getmessage[176:178] == "15":
                navigation_status = "无效信息"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")
            else:
                navigation_status = "错误"
                self.recv_text.insert(tk.END, "导航状态：" + navigation_status + "\n")


            #地面航速
            speed = int(getmessage[178:182],16) / 10
            self.recv_text.insert(tk.END, "地面航速：" + str(speed) + "\n")


            #经纬度
            get_longitude = getmessage[182:190]
            if get_longitude[0:3] == "FFFF":
                longitude = "无效"
            else:
                byte_string = bytes.fromhex(get_longitude)
                longitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (longitude < 0):
                    long_tag = "南纬: "
                    longitude = str((0 - longitude) / 10000)
                else:
                    long_tag = "北纬: "
                    longitude = str((longitude) / 10000)
            get_latitude = getmessage[190:198]
            if get_latitude[0:3] == "FFFF":
                latitude = "无效"
            else:
                byte_string = bytes.fromhex(get_latitude)
                latitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (latitude < 0):
                    lat_tag = " 西经: "
                    latitude = str((0 - latitude) / 10000)
                else:
                    lat_tag = " 东经:"
                    latitude = str((latitude) / 10000)
            if (longitude == "无效" or latitude == "无效"):
                self.recv_text.insert(tk.END, "无效位置\n")
            else:
                self.recv_text.insert(tk.END, "本机位置为: " + str(long_tag) + str(longitude) + str(lat_tag) + str(
                    latitude) + "\n")

            #地面航线
            route = int(getmessage[198:202],16) / 10
            self.recv_text.insert(tk.END, "地面航线：" + str(route) + "\n")

            # 实际航向
            heading = int(getmessage[202:206], 16)
            self.recv_text.insert(tk.END, "实际航向：" + str(heading) + "\n")

            #帧尾
            if getmessage[206:212] != "334441":
                last_type = "错误类型:帧尾错误"
                self.recv_text.insert(tk.END, last_type + "\n")
            else:
                last_type = "帧尾正确"
                self.recv_text.insert(tk.END, last_type + "\n")

                return

        # ACARS数据
        if getmessage[36:38] == "03" or getmessage[36:38] == "04" or getmessage[36:38] == "05" or getmessage[
                                                                                                  36:38] == "06":
            if 48 <= ord(getmessage[42:44][0]) <= 57 and 48 <= ord(getmessage[42:44][1]) <= 57:
                get_state = "飞机发往地面"
                self.recv_text.insert(tk.END, "上下行标识： " + get_state + "\n")
            else:
                get_state = "错误"
                self.recv_text.insert(tk.END, "上下行标识： " + get_state + "\n")
            if getmessage[44:46] == "01":
                get_mode = "A类，广播模式"
                self.recv_text.insert(tk.END, "消息模式： " + get_mode + "\n")
            elif getmessage[44:46] == "02":
                t = "B类，点对点模式"
                self.recv_text.insert(tk.END, t + "\n")
            else:
                get_mode = "错误"
                self.recv_text.insert(tk.END, "消息模式： " + get_mode + "\n")
            if getmessage[46:60] == "FFFFFFFFFFFFFF":
                mess = "无效信息"
                self.recv_text.insert(tk.END, mess + "\n")
            else:
                self.recv_text.insert(tk.END, "飞机注册码：" + getmessage[46:60] + "\n")

            self.recv_text.insert(tk.END, "航班号：" + getmessage[60:72] + "\n")
            if getmessage[72:80] == "FFFFFFFFFFFFFF":
                t = "无效信息"
                self.recv_text.insert(tk.END, t + "\n")
            else:
                self.recv_text.insert(tk.END, "起飞机场：" + getmessage[72:80] + "\n")

            if getmessage[80:88] == "FFFFFFFFFFFFFF":
                t = "无效信息"
                self.recv_text.insert(tk.END, t + "\n")
            else:
                self.recv_text.insert(tk.END, "目的机场：" + getmessage[72:80] + "\n")

            month = int(getmessage[88:90], 16)
            day = int(getmessage[90:92], 16)
            hour = int(getmessage[92:94], 16)
            minute = int(getmessage[94:96], 16)
            self.recv_text.insert(tk.END, "预计到达时间为: " + str(month) + "月" + str(day) + "日" + str(
                hour) + "时" + str(minute) + "分" "\n")

            t = int(getmessage[96:100], 16)
            self.recv_text.insert(tk.END, "空速：" + str(t) + "\n")

            get_longitude = getmessage[100:108]
            if get_longitude[0:3] == "FFFF":
                longitude = "无效"
            else:
                byte_string = bytes.fromhex(get_longitude)
                longitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (longitude < 0):
                    long_tag = "南纬: "
                    longitude = str((0 - longitude) / 10000)
                else:
                    long_tag = "北纬: "
                    longitude = str((longitude) / 10000)
            get_latitude = getmessage[108:116]
            if get_latitude[0:3] == "FFFF":
                latitude = "无效"
            else:
                byte_string = bytes.fromhex(get_latitude)
                latitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (latitude < 0):
                    lat_tag = " 西经: "
                    latitude = str((0 - latitude) / 10000)
                else:
                    lat_tag = " 东经:"
                    latitude = str((latitude) / 10000)
            if (longitude == "无效" or latitude == "无效"):
                self.recv_text.insert(tk.END, "无效位置\n")
            else:
                self.recv_text.insert(tk.END, "位置为: " + str(long_tag) + str(longitude) + str(lat_tag) + str(
                    latitude) + "\n")

            get_height = getmessage[116:124]
            self.recv_text.insert(tk.END, "高度：" + get_height + "\n")

            # 帧尾
            if getmessage[124:130] != "334441":
                last_type = "错误类型:帧尾错误"
                self.recv_text.insert(tk.END, last_type + "\n")
                return
            else:
                last_type = "帧尾正常"
                self.recv_text.insert(tk.END, last_type + "\n")


        # ADS-B数据
        if getmessage[36:38] == "07":
            get_add = getmessage[42:48]
            self.recv_text.insert(tk.END, "飞机地址码：" + get_add + "\n")

            if getmessage[48:50] == "00":
                get_type = "无 ADS-B 发射器类型信息"
            elif getmessage[48:50] == "01":
                get_type = "轻型（＜15500 磅）；"
            elif getmessage[48:50] == "02":
                get_type = "小型（15500 到 75000 磅）；"
            elif getmessage[48:50] == "03":
                get_type = "大型（75000 到 300000 磅）；"
            elif getmessage[48:50] == "04":
                get_type = "高漩涡式大型（如 B-757 飞机）"
            elif getmessage[48:50] == "05":
                get_type = "重型（＞300000 磅）；"
            elif getmessage[48:50] == "06":
                get_type = "高性能（＞5g 加速度且＞400 哩/小时）；"
            elif getmessage[48:50] == "07":
                get_type = "旋冀飞机；"
            else:
                get_type = "错误"
            self.recv_text.insert(tk.END, "飞机类别：" + get_type + "\n")


            if getmessage[50:52] == "00":
                get_dir = "向上"
            elif getmessage[50:52] == "01":
                get_dir = "向下"
            else:
                get_dir ="错误"
            self.recv_text.insert(tk.END, "飞垂直速度方向：" + get_dir + "\n")

            get_ver_speed = int(getmessage[52:56], 16)
            self.recv_text.insert(tk.END, "垂直速度：" + str(get_ver_speed) + "\n")

            get_air_speed = int(getmessage[56:60], 16)
            self.recv_text.insert(tk.END, "空速：" + str(get_air_speed) + "\n")

            get_air_dir = int(getmessage[60:64], 16) / 100
            self.recv_text.insert(tk.END, "航向：" + str(get_air_dir) + "\n")

            aim_dir = int(getmessage[64:68], 16) / 100
            self.recv_text.insert(tk.END, "目标航向：" + str(aim_dir ) + "\n")

            get_longitude = getmessage[68:76]
            if get_longitude[0:3] == "FFFF":
                longitude = "无效"
            else:
                byte_string = bytes.fromhex(get_longitude)
                longitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (longitude < 0):
                    long_tag = "南纬: "
                    longitude = str((0 - longitude) / 10000)
                else:
                    long_tag = "北纬: "
                    longitude = str((longitude) / 10000)
            get_latitude = getmessage[76:84]
            if get_latitude[0:3] == "FFFF":
                latitude = "无效"
            else:
                byte_string = bytes.fromhex(get_latitude)
                latitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (latitude < 0):
                    lat_tag = " 西经: "
                    latitude = str((0 - latitude) / 10000)
                else:
                    lat_tag = " 东经:"
                    latitude = str((latitude) / 10000)
            if (longitude == "无效" or latitude == "无效"):
                self.recv_text.insert(tk.END, "无效位置\n")
            else:
                self.recv_text.insert(tk.END, "位置为: " + str(long_tag) + str(longitude) + str(lat_tag) + str(
                    latitude) + "\n")

            get_height = getmessage[84:92]
            t8 = get_height
            self.recv_text.insert(tk.END, "高度：" + t8 + "\n")

            get_height = getmessage[92:100]
            t9 = get_height
            self.recv_text.insert(tk.END, "目标高度：" + t9 + "\n")

            t10 = getmessage[100:116]
            self.recv_text.insert(tk.END, "航班号：" + t10 + "\n")

            # 帧尾
            if getmessage[116:122] != "334441":
                last_type = "错误类型:帧尾错误"
                self.recv_text.insert(tk.END, last_type + "\n")
                return
            else:
                last_type = "帧尾正常"
                self.recv_text.insert(tk.END, last_type + "\n")

        # 工况信息
        if getmessage[36:38] == "FF":
            get_frequency1 = getmessage[42:50]
            byte_string = bytes.fromhex(get_frequency1)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "通道1中心频率为" + str(frequency) + "KHz\n")

            get_frequency2 = getmessage[58:66]
            byte_string = bytes.fromhex(get_frequency2)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "通道2中心频率为" + str(frequency) + "KHz\n")

            get_frequency3 = getmessage[74:82]
            byte_string = bytes.fromhex(get_frequency3)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "通道3中心频率为" + str(frequency) + "KHz\n")

            get_frequency4 = getmessage[90:98]
            byte_string = bytes.fromhex(get_frequency4)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "通道4中心频率为" + str(frequency) + "KHz\n")

            get_frequency5 = getmessage[106:114]
            byte_string = bytes.fromhex(get_frequency5)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "通道5中心频率为" + str(frequency) + "KHz\n")

            get_frequency6 = getmessage[122:130]
            byte_string = bytes.fromhex(get_frequency6)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "通道6中心频率为" + str(frequency) + "KHz\n")

            get_frequency7 = getmessage[138:146]
            byte_string = bytes.fromhex(get_frequency7)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "通道7中心频率为" + str(frequency) + "KHz\n")

            get_fpga = getmessage[154:170]
            #去掉头部的0
            fpga = get_fpga.lstrip('0')
            self.recv_text.insert(tk.END, "FPGA版本号为" + str(fpga) + "\n")

            get_arm =  getmessage[170:186]
            arm = get_arm.lstrip('0')
            self.recv_text.insert(tk.END, "ARM版本号为" + str(arm) + "\n")

            # 四个字节，分别对应第一到第四段号码
            address1 = int(getmessage[186:188], 16)
            address2 = int(getmessage[188:190], 16)
            address3 = int(getmessage[190:192], 16)
            address4 = int(getmessage[192:194], 16)
            ip_address = str(address1) + "." + str(address2) + "." + str(address3) + "." + str(address4)
            self.recv_text.insert(tk.END, "接收机地址为" + str(ip_address) + "\n")

            get_port =  getmessage[194:198]
            self.recv_text.insert(tk.END, "接收机端口号为" + str(get_port) + "\n")


            # 198-202 纬度
            get_longitude = getmessage[198:206]
            if get_longitude[0:3] == "FFFF":
                longitude = "无效"
            else:
                byte_string = bytes.fromhex(get_longitude)
                longitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (longitude < 0):
                    long_tag = "南纬: "
                    longitude = str((0 - longitude) / 10000)
                else:
                    long_tag = "北纬: "
                    longitude = str((longitude) / 10000)
            get_latitude = getmessage[206:214]
            if get_latitude[0:3] == "FFFF":
                latitude = "无效"
            else:
                byte_string = bytes.fromhex(get_latitude)
                latitude = int.from_bytes(byte_string, byteorder='little', signed=True)
                if (latitude < 0):
                    lat_tag = " 西经: "
                    latitude = str((0 - latitude) / 10000)
                else:
                    lat_tag = " 东经:"
                    latitude = str((latitude) / 10000)
            if (longitude == "无效" or latitude == "无效"):
                self.recv_text.insert(tk.END, "无效位置\n")
            else:
                self.recv_text.insert(tk.END, "本机位置为: " + str(long_tag) + str(longitude) + str(lat_tag) + str(latitude) + "\n")

            cpu_temp = getmessage[214:216]
            self.recv_text.insert(tk.END, "CPU温度为" + str(cpu_temp) + "℃\n")

            # 帧尾
            if getmessage[216:222] != "334441":
                last_type = "错误类型:帧尾错误"
                self.recv_text.insert(tk.END, last_type + "\n")
                return


if __name__ == "__main__":
    water = 0
    root = tk.Tk()
    app = ReceiveApp(root)
    root.mainloop()

