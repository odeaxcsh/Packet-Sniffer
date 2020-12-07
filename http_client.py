import requests
import time
from sys import argv
from threading import Thread

refreshed = False
auto_refresh = False
auto_refresh_delay = 15
manual_refresh = True
address = '127.0.0.1'
port = 80

def get_page():
    address_ = 'http://' + address + ':' + str(port)
    print("Receiving:", address_)
    try:
        web_page = requests.get(address_)
        print("Completed: \n", web_page.text)
    except Exception as e:
        print("Error in receiving data:", str(e))

def check():
    global refreshed, auto_refresh_delay
    while True:
        time.sleep(auto_refresh_delay)
        if not refreshed:
            print("[Automatic refresh..]")
            get_page()
            if manual_refresh:
                print("Press Enter to receive data again or enter exit to exit:", end=' ')
        else: 
            refreshed = False

if __name__ == '__main__':
    i = 1
    while i < len(argv):
        if argv[i] == '-m':
            manual_refresh = False
        elif argv[i] == '-a':
            auto_refresh = True
        elif argv[i] == '--delay':
            i += 1
            auto_refresh_delay = int(argv[i])
        else:
            if len(argv[i]) < 6:
                port = argv[i]
            else:
                address = argv[i]
        i += 1
    
    if auto_refresh:
        Thread(target=check).start()

    if manual_refresh:
        while True:
            if input("Press Enter to receive data again or enter exit to exit: ").lower() == 'exit':
                break
            else:
                get_page()
            refreshed = True