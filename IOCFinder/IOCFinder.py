import re
import requests
import json
from bs4 import BeautifulSoup
import pymongo


def ioc_reporter():
    file = open('ioc_report.txt', 'w')
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient['IOC']
    mycol = mydb['ioc']
    base_url_iot = 'https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/'
    response = requests.get('https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/tree/main',
                            allow_redirects=True, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'})
    content = response.content
    soup = BeautifulSoup(content, 'html.parser', from_encoding="iso-8859-1")
    results = soup.find_all('script', attrs={'data-target': 'react-partial.embeddedData'})
    regex = r'"tree":{"items":\[{"name":'
    for result in results:
        if re.search(regex, result.text):
            json_result = json.loads(result.text)
            iot_links = json_result['props']['initialPayload']['tree']['items']
            for link in iot_links:
                ioc_link = base_url_iot + link['path']
                json_ioc = {'ioc': ioc_link}
                if mycol.count_documents({'ioc': ioc_link}, limit=1) != 0:
                    continue
                mycol.insert_one(json_ioc)
                file.write(json_ioc['ioc']+'\n')


ioc_reporter()
