# 接收机，相当于本机（192.168.49.10，端口号为 5010）
#，上行报文指接收机发送给上位机
from getdata import *
import tkinter as tk
from threading import Thread,Timer
import socket
import time
from threading import Thread, Event

class SendApp:
    def __init__(self, window):
        self.window = window
        self.window.title("模拟接收机，发上行报文，接收下行报文")
        
        

        # 创建发送区域的主框架
        self.send_frame = tk.Frame(window)
        self.send_frame.pack(padx=10, pady=10)

        # 创建专门的发送数据子框架
        self.send_data_frame = tk.Frame(self.send_frame)
        self.send_data_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        self.send_label = tk.Label(self.send_data_frame, text="发送数据")
        self.send_label.pack(side=tk.LEFT)
        self.send_entry = tk.Entry(self.send_data_frame, width=50)
        self.send_entry.pack(side=tk.LEFT)

        # 创建元数据子框架
        self.metadata_frame = tk.LabelFrame(self.send_frame, text='元数据', padx=10, pady=10)
        self.metadata_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        # 输入帧头
        self.first_message_label = tk.Label(self.metadata_frame, text="帧头:")
        self.first_message_label.grid(row=0, column=0)
        self.first_message_entry = tk.Entry(self.metadata_frame)
        self.first_message_entry.grid(row=0, column=1)

        # 流水号
        self.flow_msg_label = tk.Label(self.metadata_frame, text="流水号:")
        self.flow_msg_label.grid(row=0, column=2)
        self.flow_msg_entry = tk.Entry(self.metadata_frame)
        self.flow_msg_entry.grid(row=0, column=3)

        #实际时间
        self.actual_time_label = tk.Label(self.metadata_frame, text="实际时间:")
        self.actual_time_label.grid(row=0, column=6)
        self.actual_time_entry = tk.Entry(self.metadata_frame)
        self.actual_time_entry.grid(row=0, column=7)

        # 时标
        self.time_msg_label = tk.Label(self.metadata_frame, text="时标:")
        self.time_msg_label.grid(row=0, column=4)
        self.time_msg_entry = tk.Entry(self.metadata_frame)
        self.time_msg_entry.grid(row=0, column=5)

        # 输入帧尾
        self.last_message_label = tk.Label(self.metadata_frame, text="帧尾:")
        self.last_message_label.grid(row=1, column=0)
        self.last_message_entry = tk.Entry(self.metadata_frame)
        self.last_message_entry.grid(row=1, column=1)

        # 报文类型 & 数据长度 & 数据段
        self.payload_frame = tk.LabelFrame(self.send_frame, text='有效负载', padx=10, pady=10)
        self.payload_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        # 报文类型
        self.type_msg_label = tk.Label(self.payload_frame, text="报文类型:")
        self.type_msg_label.grid(row=0, column=0)
        self.type_msg_entry = tk.Entry(self.payload_frame)
        self.type_msg_entry.grid(row=0, column=1)

        # 数据长度
        self.length_msg_label = tk.Label(self.payload_frame, text="数据长度:")
        self.length_msg_label.grid(row=0, column=2)
        self.length_msg_entry = tk.Entry(self.payload_frame)
        self.length_msg_entry.grid(row=0, column=3)

        # 数据段
        self.data_msg_label = tk.Label(self.payload_frame, text="数据段:")
        self.data_msg_label.grid(row=1, column=0)
        self.data_msg_entry = tk.Entry(self.payload_frame)
        self.data_msg_entry.grid(row=1, column=1)

        # 创建发送按钮
        self.send_button = tk.Button(self.send_frame, text="发送", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, pady=10)
        # 添加停止按钮
        self.stop_button = tk.Button(self.send_frame, text="停止", command=self.stop_sending_messages)
        self.stop_button.pack(side=tk.LEFT, pady=10)
        # 初始化停止标志
        self.stop_flag = False
        # 接收区域
        self.recv_frame = tk.Frame(window)
        self.recv_frame.pack(padx=10, pady=10)

        self.recv_text = tk.Text(self.recv_frame, height=40, width=50)
        self.recv_text.pack(expand=True, fill="both")

        # 创建udp对象
        self.sk = socket.socket(type=socket.SOCK_DGRAM)
        self.sk.bind(("127.0.0.1", 5010))

        # 开始接收数据的线程
        self.thread = Thread(target=self.receive_data)
        # 运行解析下行报文函数
        self.thread.daemon = True
        self.thread.start()


        # 启动定时发送ACARS和ADSB报文
        self.start_sending_messages()
        
    def start_sending_messages(self):
        # 发送ACARS报文
        '''
        acars_msg = get_ACARS_message()
        self.sk.sendto(acars_msg.encode(), ("127.0.0.1", 8080))
        # 发送ADSB报文
        adsb_msg = get_ADSB_message()
        self.sk.sendto(adsb_msg.encode(), ("127.0.0.1", 8080))
        '''
        if not self.stop_flag:
            msg = get_Aero_message()
            self.sk.sendto(msg.encode(), ("127.0.0.1", 8080))
            # 设置定时器，每10秒发送一次
            Timer(10, self.start_sending_messages).start()
        #msg = get_Aero_message()
        #self.sk.sendto(msg.encode(), ("127.0.0.1", 8080))
        
        # 设置定时器，每10秒发送一次
        Timer(1, self.start_sending_messages).start()
    
    def stop_sending_messages(self):
        # 设置停止标志为True，停止发送消息
        self.stop_flag = True
    
    def send_message(self):
        msg = self.send_entry.get()
        msg = msg.replace(" ", "")
        if msg == "":
            head = self.first_message_entry.get()
            flow = self.flow_msg_entry.get()
            times = self.actual_time_entry.get()
            time_count = self.time_msg_entry.get()
            types = self.type_msg_entry.get()
            length = self.length_msg_entry.get()
            data_get = self.data_msg_entry.get()
            data = "".join(data_get.split(" "))
            last = self.last_message_entry.get()
            msg = head + flow + times + time_count + types + length + data + last
        #发送数据
        self.sk.sendto(msg.encode(), ("127.0.0.1", 8080))
        time.sleep(1)

    def receive_data(self):
        while True:
            #接收数据
            msg, addr = self.sk.recvfrom(1024)
            message_to_display = "Received: " + msg.decode() + " from " + str(addr)
            self.recv_text.insert(tk.END, message_to_display + "\n")
            self.analysis_message(msg)
    # 下行报文18字节固定长度
    """帧格式：
        0~3     帧头    BYTE[8:10]    4         固定为0x58443341
        4       指令类型 UINT8      1         0x00:开始停止       0x01:工况查询       0x02:设备重置    0x03:授时指令      0x04:频率设置   
                                            0x05:本机地址设置   0x06:本机位置设置     0x07:开启关闭测试模式
        5~14    指令内容 BYTE[10]   10       根据指令类型填充，当指令类型为0x01、0x02时可不填充
        15~17   帧尾    BYTE[3]     3       固定为0x334441
    """
    #解析下行报文
    def analysis_message(self, msg):
        getmessage = msg.decode()
        #如果帧头不是0x58443341，则报文错误

        if getmessage[0:8] != "58443341":
            first_type = "错误类型:帧头错误"
            self.recv_text.insert(tk.END, first_type + "\n")
            return
        #解析指令类型
        #指令为00，开始停止
        if getmessage[8:10] == "00":
            instruction_type = "指令类型:开始停止"
            self.recv_text.insert(tk.END, instruction_type + "\n")
            if getmessage[10:14] == "AAAA":
                start_stop = "开始上传解调数据"
                self.recv_text.insert(tk.END, start_stop + "\n")
            elif getmessage[10:14] == "5555":
                start_stop = "停止传输解调数据"
                self.recv_text.insert(tk.END, start_stop + "\n")
            else:
                start_stop = "指令"
                self.recv_text.insert(tk.END, start_stop + "\n")
            
        elif getmessage[8:10] == "01":
            instruction_type = "指令类型:工况查询"
            self.recv_text.insert(tk.END, instruction_type + "\n")
        elif getmessage[8:10] == "02":
            instruction_type = "指令类型:设备重置"
            self.recv_text.insert(tk.END, instruction_type + "\n")
        elif getmessage[8:10] == "03":
            instruction_type = "指令类型:授时指令"
            self.recv_text.insert(tk.END, instruction_type + "\n")
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
            year = int(getmessage[10:12],16)+2000
            month = int(getmessage[12:14],16)
            day = int(getmessage[14:16],16)
            hour = int(getmessage[16:18],16)
            minute = int(getmessage[18:20],16)
            second = int(getmessage[20:22],16)
            self.recv_text.insert(tk.END, "设置时间为: " + str(year) + "年" + str(month) + "月" + str(day) + "日" + str(hour) + "时" + str(minute) + "分" + str(second) + "秒\n")
        elif getmessage[8:10] == "04":
            instruction_type = "指令类型:频率设置"
            self.recv_text.insert(tk.END, instruction_type + "\n")
            """
            0    通道号    UINT8    1       0-3,表示ACARS的通道0-3
            1-4  频率      UINT32   4      单位KHz
            5-9  保留
            """
            channel = int(getmessage[10:12],16)
            get_frequency = getmessage[12:18]
            byte_string = bytes.fromhex(get_frequency)
            frequency = int.from_bytes(byte_string, byteorder='little')
            self.recv_text.insert(tk.END, "ACARS通道" + str(channel) + "的频率为" + str(frequency) + "KHz\n")
        elif getmessage[8:10] == "05":
            instruction_type = "指令类型:本机地址设置"
            self.recv_text.insert(tk.END, instruction_type + "\n")
            """
            0-3  本机地址    UINT32    4 四个字节，分别对应第一到第四段号码
            4-9  保留
            """
            #四个字节，分别对应第一到第四段号码
            address1 = int(getmessage[10:12],16)
            address2 = int(getmessage[12:14],16)
            address3 = int(getmessage[14:16],16)
            address4 = int(getmessage[16:18],16)
            ip_address = str(address1)+"."+str(address2)+"."+str(address3)+"."+str(address4)
            self.recv_text.insert(tk.END, "本机地址为" + str(ip_address) + "\n")
        elif getmessage[8:10] == "06":
            instruction_type = "指令类型:本机位置设置"
            self.recv_text.insert(tk.END, instruction_type + "\n")
            """
            0-3  经度    UINT32    4      单位：0.0001度，范围-90.000090.0000，北纬为正，南纬为负。如0xFFFB4D4D表示南纬30.7891度。0xFFFF表示无效。
            4-7  纬度    UINT32    4      单位：0.0001度，范围-180.0000180.0000。东经为正，西经为负。如0x001128D7表示东经112.4567度。0xFFFF表示无效：
            8-9  保留
            """
            get_longitude = getmessage[10:18]
            if get_longitude[0:3] == "FFFF":
                longitude = "无效"
            else:
                byte_string = bytes.fromhex(get_longitude)
                longitude = int.from_bytes(byte_string, byteorder='little',signed=True)
                if(longitude < 0):
                    long_tag = "南纬: "
                    longitude = str((0-longitude)/10000)
                else:
                    long_tag = "北纬: "
                    longitude = str((longitude)/10000)
            get_latitude = getmessage[18:26]
            if get_latitude[0:3] == "FFFF":
                latitude = "无效"
            else:
                byte_string = bytes.fromhex(get_latitude)
                latitude = int.from_bytes(byte_string, byteorder='little',signed=True)
                if(latitude < 0):
                    lat_tag = " 西经: "
                    latitude = str((0-latitude)/10000)
                else:
                    lat_tag = " 东经:"
                    latitude = str((latitude)/10000)
            if(longitude == "无效" or latitude == "无效"):
                self.recv_text.insert(tk.END, "无效位置\n")
            else:
                self.recv_text.insert(tk.END, "本机位置为: " + str(long_tag) +  str(longitude) + str(lat_tag) + str(latitude) + "\n")
        elif getmessage[8:10] == "07":
            instruction_type = "指令类型:开启关闭测试模式"
            self.recv_text.insert(tk.END, instruction_type + "\n")
            if getmessage[10:14] == "AAAA":
                start_stop = "开启测试模式"
                self.recv_text.insert(tk.END, start_stop + "\n")
            elif getmessage[10:14] == "5555":
                start_stop = "关闭测试模式"
                self.recv_text.insert(tk.END, start_stop + "\n")
            else:
                start_stop = "开关测试指令错误"
                self.recv_text.insert(tk.END, start_stop + "\n")
        else:
            instruction_type = "指令类型:错误"
            self.recv_text.insert(tk.END, instruction_type + "\n")

        #如果帧尾不是0x334441，则报文错误
        if getmessage[30:36] != "334441":
            last_type = "错误类型:帧尾错误"
            self.recv_text.insert(tk.END, last_type + "\n")
            return



if __name__ == "__main__":
    root = tk.Tk()
    app = SendApp(root)
    root.mainloop()