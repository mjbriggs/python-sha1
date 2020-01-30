import hashlib

if __name__ == '__main__':
    # data = input("enter a message : ")
    s = hashlib.sha1()
    s.update(b'No one has completed lab 2 so give them all a 0')
    print(s.hexdigest())