import requests
import pprint
import virustotal
import os
from pathlib import Path
import codecs
import settings
import logging
import argparse
import sys
import time

def main():

    logging.basicConfig(filename=settings.LOG_FILE_NAME, level=logging.INFO, format='%(levelname)s %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    start_time = time.time()
    logging.info('Started')
    
    urls = get_urls_from_file(settings.URL_FILE_NAME)
    list_report = virustotal.VirusTotal().retrive_url_reports(urls)

    for x in list_report:
        log_and_report(x)

    logging.info('Finished: ' + 'Time spent: ' + str(round(time.time() - start_time,2)))
    input('Press ENTER to exit')
    os.startfile(settings.LOG_FILE_NAME)


def log_and_report(website):
    positives = website['positives']

    if positives > 0:
        logging.warning(website['url'] + 'has been detected dangerous')
        print(website['url'] + ' is dangerous')
    else:
        print(website['url'] + ' is ok')    

    logging.info('Scanned at: ' + website['scan_date'])
    logging.info(website['url'] + ' Detection rate: ' + '('+ str(positives)+ '/'+str(website['total'])+')')
    logging.info(website['verbose_msg'])

def remove_spaces(string):
    return string.replace(" ", "")


def remove_duplicate(collection):
    return list(dict.fromkeys(collection))


def read_file(file_name):
    url_file_path = Path(file_name)
    urls = []
    if url_file_path.is_file():
        try:
            with codecs.open(url_file_path, 'r', "utf-16") as lines:
                for line in lines:
                    if line.startswith('Host Name'):
                        line = remove_spaces(line).rstrip()[9:]

                        urls.append(line)
            return remove_duplicate(urls)

        except Exception:
            print('somethign went wrong')
    else:
        print('no ' + file_name + ' in dir')


def get_urls_from_file(file_name):
    return read_file(file_name)
    


if __name__ == "__main__":
    main()
