import random
import string
from datetime import datetime

def get_current_time_hex():
    current_time = datetime.now()
    year = current_time.year %100
    month = current_time.month
    day = current_time.day
    hour = current_time.hour
    minute = current_time.minute
    second = current_time.second
    year_hex = f"{year:02x}".upper()
    month_hex = f"{month:02x}".upper()
    day_hex = f"{day:02x}".upper()
    hour_hex = f"{hour:02x}".upper()
    minute_hex = f"{minute:02x}".upper()
    second_hex = f"{second:02x}".upper()
    formatted_time_hex = year_hex + month_hex + day_hex + hour_hex + minute_hex + second_hex
    return formatted_time_hex
def choose_random_from_list():
    options = [ 3, 4, 5, 6, 7]
    op=random.choice(options)
    return f"{op:02x}".upper()
def get_random_UPsigns():
    return random.choice(string.ascii_letters)+random.choice(string.ascii_letters)
def get_random_0XFF(a,b):
    XFF = random.randint(a, b)
    return f"{XFF:02x}".upper()
def get_random_alphanumeric():
    return random.choice(string.ascii_letters + string.digits)
def get_ACARS_message():
    UPsigns = get_random_UPsigns()
    messmode = get_random_0XFF(1,2)
    registration=""
    number=""
    qfairport=""
    mdairport=""
    for i in range(7):                      
        registration+=get_random_0XFF(0,255)
    for i in range(12):
        number+=get_random_alphanumeric()
    for i in range(4):
        qfairport+=get_random_0XFF(0,255)
    for i in range(4):
        mdairport+=get_random_0XFF(0,255)
    ETA=get_random_0XFF(1,12)+get_random_0XFF(1,31)+get_random_0XFF(0,3)+get_random_0XFF(0,59)
    CAS=get_random_0XFF(0,255)+get_random_0XFF(0,255)
    longitude=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    dimension=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    high=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    ACARSmsg = UPsigns+messmode+registration+number+qfairport+mdairport+ETA+CAS+longitude+dimension+high
    return ACARSmsg
def get_ADSB_message():
    ICAO=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    type=get_random_0XFF(0,7)
    verticaltoward=get_random_0XFF(0,1)
    verticalspeed=get_random_0XFF(0,255)+get_random_0XFF(0,255)
    CAS1=get_random_0XFF(0,255)+get_random_0XFF(0,255)
    course=get_random_0XFF(0,255)+get_random_0XFF(0,255)
    mbcourse=get_random_0XFF(0,255)+get_random_0XFF(0,255)
    longitude1=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    dimension1=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    high1=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    mbhigh=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    number1=""
    for i in range(16):
        number1+=get_random_alphanumeric()
    ADSBmsg=ICAO+type+verticaltoward+verticalspeed+CAS1+course+mbcourse+longitude1+dimension1+high1+mbhigh+number1
    return ADSBmsg
def get_Aero_message():
    head="58443341"
    end="334441"
    water=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    time=get_current_time_hex()
    times=get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)+get_random_0XFF(0,255)
    types=choose_random_from_list()
    longth="FF"
    if types=="07":
        longth=f"{36:04}".upper()
        msg = get_ADSB_message()
    else:
        longth=f"{40:04}".upper()
        msg=get_ACARS_message()
    message=head+water+time+times+types+longth+msg+end
    return message
with open("灰机.txt","w") as f:
    for i in range(10000):
        f.write(get_Aero_message())
    print("ok")