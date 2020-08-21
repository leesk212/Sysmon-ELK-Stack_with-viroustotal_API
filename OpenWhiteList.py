def to_make_whitelist(filedirectory):
    whitelist = []
    f = open(filedirectory,"rt")
    while True:
        temp = []
        text = f.readline()
        if not text:break
        filename=(text[text.find('=')+1:text.find('/')])
        Hash=(text[text.find('=',text.find('/'))+1:text.find('\n')])
        temp.append(filename)
        temp.append(Hash)
        whitelist.append(temp)
    f.close()
    return whitelist

def to_make_whitelist_in_local_directory(filedirectory,whitelist):
    f = open(filedirectory+"whitelist.txt","w+")
    for a in range(len(whitelist)):
        f.write(whitelist[a]+'\n')

    f.close()
