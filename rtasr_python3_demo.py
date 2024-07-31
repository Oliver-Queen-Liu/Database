# -*- encoding:utf-8 -*-
import hashlib
import hmac
import base64
from socket import *
import json, time, threading
from websocket import create_connection
import websocket
from urllib.parse import quote
import logging
import pyaudio

# reload(sys)
# sys.setdefaultencoding("utf8")
class Client():
    def __init__(self):
        base_url = "ws://rtasr.xfyun.cn/v1/ws"
        ts = str(int(time.time()))
        tt = (app_id + ts).encode('utf-8')
        md5 = hashlib.md5()
        md5.update(tt)
        baseString = md5.hexdigest()
        baseString = bytes(baseString, encoding='utf-8')

        apiKey = api_key.encode('utf-8')
        signa = hmac.new(apiKey, baseString, hashlib.sha1).digest()
        signa = base64.b64encode(signa)
        signa = str(signa, 'utf-8')
        self.end_tag = "{\"end\": true}"

        self.ws = create_connection(base_url + "?appid=" + app_id + "&ts=" + ts + "&signa=" + quote(signa))
        self.trecv = threading.Thread(target=self.recv)
        self.trecv.start()

    def send(self, file_path):
        file_object = open(file_path, 'rb')
        try:
            index = 1
            while True:
                chunk = file_object.read(1280)
                if not chunk:
                    break
                self.ws.send(chunk)

                index += 1
                time.sleep(0.04)
        finally:
            file_object.close()

        self.ws.send(bytes(self.end_tag.encode('utf-8')))
        print("send end tag success")
        
    def rt_send(self, chunk_size=1024, sample_rate=16000, channels=1):
        # 初始化PyAudio并打开音频流
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=channels,
                        rate=sample_rate, input=True, frames_per_buffer=chunk_size)

        # 开始音频流
        stream.start_stream()

        try:
            while True:
                # 从麦克风读取音频数据
                audio_data = stream.read(chunk_size)
                # 发送到服务器
                self.ws.send(audio_data)

                # 可以在这里添加逻辑来决定何时停止发送，例如检测静音或达到特定时间
                # if self.should_stop(audio_data):
                #     break

        except KeyboardInterrupt:
            # 用户中断时的处理
            pass
        finally:
            # 停止音频流并关闭资源
            stream.stop_stream()
            stream.close()
            p.terminate()

        # 发送结束标签
        self.ws.send(bytes(self.end_tag.encode('utf-8')))
        print("send end tag success")

    def recv(self):
        try:
            while self.ws.connected:
                result = str(self.ws.recv())
                if len(result) == 0:
                    print("receive result end")
                    break
                result_dict = json.loads(result)
                # 解析结果
                if result_dict["action"] == "started":
                    print("handshake success, result: " + result)

                if result_dict["action"] == "result":
                    result_1 = result_dict
                    # result_2 = json.loads(result_1["cn"])
                    # result_3 = json.loads(result_2["st"])
                    # result_4 = json.loads(result_3["rt"])
                    print("rtasr result: " + result_1["data"])

                if result_dict["action"] == "error":
                    print("rtasr error: " + result)
                    self.ws.close()
                    return
        except websocket.WebSocketConnectionClosedException:
            print("receive result end")

    def close(self):
        self.ws.close()
        print("connection closed")


if __name__ == '__main__':
    logging.basicConfig()

    app_id = "bdc8a74f"
    api_key = "af8b855977814f4c4b3718255f24dea3"
    file_path = r"./test_1.pcm"

    client = Client()
    #client.send(file_path)
    client.rt_send()
