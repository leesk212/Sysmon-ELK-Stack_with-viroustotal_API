

def OpenWhiteList(filedirectory):
    whitelist = []
    f = open(filedirectory,"rt")
    while True:
        temp = []
        text = f.readline()
        if not text:break
        filename=(text[text.find(':')+1:text.find('/')])
        Hash=(text[text.find(':',text.find('/'))+1:text.find('\n')])
        temp.append(filename)
        temp.append(Hash)
        whitelist.append(temp)
    return whitelist
