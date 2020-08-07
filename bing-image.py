#!/usr/bin/env python3
from bs4 import BeautifulSoup
import sys
import urllib.request


def get_soup(url,header):
    #return BeautifulSoup(urllib2.urlopen(urllib2.Request(url,headers=header)),
    # 'html.parser')
    return BeautifulSoup(urllib.request.urlopen(
        urllib.request.Request(url,headers=header)),
        'html.parser')


query = '+'.join(sys.argv[1].split())

url= "https://www.bing.com/search?q={0}&sp=0&pq={0}&sc=0-100&qs=n&sk=1&first={1}&FORM=PERE"

#add the directory for your image here
header={'User-Agent':"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.134 Safari/537.36"}

foundUrls = []# contains the link for Large original images, type of  image

for x in range(0, int(sys.argv[2]), 10):
    soup = get_soup(url.format(query, x),header)

    for li in soup.find_all("li",{"class":"b_algo"}):
        #print a
        mad = li.h2.a.get("href")

        print(mad)

        foundUrls.append(mad)

print("there are total" , len(foundUrls),"urls")

##print images
with open("urls.txt", "w") as f:
    for url in foundUrls:
        try:
            f.write(url + "\n")

        except Exception as e:
            print("could not load : " + url)
            print(e)