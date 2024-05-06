# 接收机，相当于本机（192.168.49.10，端口号为 5010）
#，上行报文指接收机发送给上位机
import tkinter as tk
from threading import Thread
import socket
import time
import random
import string
import uuid
import binascii

def generate_random_user_id():
    # 生成一个随机的UUID
    random_uuid = uuid.uuid4()
    # 将UUID转换为十六进制字符串
    hex_uuid = random_uuid.hex
    # 取前10个字符（5字节）作为user_id
    user_id = hex_uuid[:10].upper()
    # 返回user_id的十六进制表示
    return user_id


def generate_random_imo_number(byte_length=4):
    # 生成一个随机数，范围为0到2^32-1（四字节无符号整数的最大值）
    random_value = random.randint(0, 2 ** 32 - 1)

    # 将生成的随机数转换为16进制表示，并格式化为指定长度的字符串
    # 使用format函数的'X'选项转换为大写16进制，zfill用于填充到指定的位数
    hex_imo_number = format(random_value, 'X').zfill(byte_length * 2).upper()

    return hex_imo_number


def generate_random_call_sign(length=14):
    # 定义16进制字符集
    hex_chars = string.digits + 'ABCDEF'

    # 随机选择字符集里的字符来生成呼号
    call_sign = ''.join(random.choice(hex_chars) for _ in range(length))

    return call_sign.upper()  # 转换为大写以符合常见的表示习惯


def generate_random_hex_boat_name(length=40):
    # 定义16进制字符集
    hex_chars = string.digits + 'ABCDEF'

    # 随机选择字符集里的字符来生成船名
    boat_name = ''.join(random.choice(hex_chars) for _ in range(length))

    return boat_name

# 假设船舶宽度和长度的范围以及所需的位数
min_width = 5  # 最小宽度，单位：米
max_width = 20  # 最大宽度，单位：米
width_digits = 4  # 宽度数值的位数

min_length = 50  # 最小长度，单位：米
max_length = 200  # 最大长度，单位：米
length_digits = 4  # 长度数值的位数


def generate_random_ship_dimension(min_value, max_value):
    # 生成一个在指定范围内的随机数
    random_value = random.randint(min_value, max_value)

    # 将生成的随机数转换为4位16进制字符串，并确保字符串是大写的
    hex_dimension = format(random_value, '04X').zfill(4).upper()

    return hex_dimension


def generate_random_eta():
    # 生成随机的月、日、时、分
    month = random.randint(1, 12)
    day = random.randint(1, 31)
    hour = random.randint(0, 23)
    minute = random.randint(0, 59)

    # 将生成的值格式化为16进制字符串，并拼接在一起
    eta = f"{month:02X}{day:02X}{hour:02X}{minute:02X}"

    return eta

def generate_random_draught_str():
    # 生成一个0到255之间的随机整数
    random_draught = random.randint(0, 255)
    # 将整数转换为两位数的16进制字符串，并确保字符串为大写
    draught_str = format(random_draught, '02X')
    return draught_str

def generate_random_destination(length=40):
    # 定义可用的字符集，这里使用大写字母和数字
    char_set = string.ascii_uppercase + string.digits
    # 使用random.choices随机选择length个字符
    destination = ''.join(random.choices(char_set, k=length))
    return destination


def generate_random_SOG():
    # 生成一个0到1022之间的随机整数
    random_sog = random.randint(0, 1022)
    # 将SOG转换为16进制表示，单位为0.1节
    # 因为SOG的范围是0.1节，所以需要将随机整数乘以10
    hex_sog = format(random_sog, '04X')  # 格式化为4位16进制数
    return hex_sog.upper()  # 确保字母为大写


def generate_random_latitude():
    while True:
        # 生成一个介于-90000到89999之间的随机整数
        random_int = random.randint(-900000, 899999)
        # 转换为16进制，并去掉前导的0xFF，如果存在的话
        hex_latitude = format(abs(random_int), '08X')[2:].upper()
        # 检查生成的16进制数是否以FF开头，若是则重新生成
        if not hex_latitude.startswith('FF'):
            break

    # 根据随机整数的正负，构造最终的8位16进制字符串
    if random_int < 0:
        # 南纬，前面补上0xFF
        hex_latitude = 'FF' + hex_latitude
    else:
        # 北纬，前面补上0x00
        hex_latitude = '00' + hex_latitude

    return hex_latitude


def generate_random_longitude():
    while True:
        # 生成一个介于-180000到179999之间的随机整数
        random_longitude = random.randint(-1800000, 1799999)
        # 转换为16进制表示，去掉前导的0xFF（如果是西经）或0xFFFF（如果是无效值）
        hex_longitude = format(abs(random_longitude), '08X')[2:].upper()
        # 检查生成的16进制数是否以FF开头，若是则重新生成
        if not hex_longitude.startswith('FF'):
            break

    # 根据随机整数的正负，构造最终的8位16进制字符串
    if random_longitude >= 0:
        # 东经，前面补上0x00
        hex_longitude = '00' + hex_longitude
    else:
        # 西经，前面补上0xFF
        hex_longitude = 'FF' + hex_longitude

    return hex_longitude

def generate_random_GOG():
    # 生成一个介于0到3599之间的随机整数
    random_GOG = random.randint(0, 3599)
    # 转换为16进制表示，确保为4位数（两位字节）
    hex_GOG = format(random_GOG, '04X').upper()
    return hex_GOG


def generate_random_course():
    # 生成一个介于0到359之间的随机整数
    random_course = random.randint(0, 359)
    # 转换为16进制表示，确保为4位数（两位字节）
    hex_course = format(random_course, '04X').upper()
    # 返回去除前缀0x的16进制字符串
    return hex_course

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


    def send_message(self):
        '''
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
        '''
	# my message
        head = "58443341"
        last = "334441"		# getmessage[202:206]
        flow = "00000000"  	# flow = flow + 1
        times = "180501052013" 	# 16 + 8 = 24
        time_count = "01020304"	#秒内计数器
        types = random.choice(["01", "02"])		#船都是AIS信息，01 or 02
        length = "0052"		# getmessage[38:42]

        data_id = random.choice(["01", "02", "03", "05", "12", "24"])
        user_id = generate_random_user_id()
        IMO = generate_random_imo_number()
        call = generate_random_call_sign()
        boat_name = generate_random_hex_boat_name()
        boat_type = random.choice(["00", "01", "02", "03","04", "05", "06", "07", "15", "20", "2B", "32", "33", "34", "35", "36", "37", "3A", "3B", "3C", "46", "50", "FF"])
        boat_width = generate_random_ship_dimension(min_width, max_width)
        boat_length = generate_random_ship_dimension(min_length, max_length)
        ETA = generate_random_eta()
        now_steady_max_dep = generate_random_draught_str()
        destination = generate_random_destination()
        state = random.choice(["00", "01", "02", "03","04", "05", "06", "07", "08", "15"])
        SOG = generate_random_SOG()
        latitude = generate_random_latitude()
        altitude = generate_random_longitude()
        GOG = generate_random_GOG()
        direction = generate_random_course()
        data = data_id + user_id + IMO + call + boat_name + boat_type + boat_width + boat_length + ETA + now_steady_max_dep + destination + state + SOG + latitude + altitude + GOG + direction
        msg = head + flow + times + time_count + types + length + data + last

        counter = 0  # 初始化计数器
        while counter < 10:  # 设置循环条件为发送次数小于10
            self.sk.sendto(msg.encode(), ("127.0.0.1", 8080))  # 发送消息
            time.sleep(1)  # 暂停1秒
            counter += 1  # 增加发送次数计数器

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