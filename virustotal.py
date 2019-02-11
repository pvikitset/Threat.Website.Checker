import threat_website
import json
import requests
import pprint
import time
import virustotalconst

class VirusTotal(object):
    def __init__(self):
        self.api_key = virustotalconst.API_KEY
        self.url_base = virustotalconst.URL_BASE
        self.public_api_sleep_time = virustotalconst.PUBLIC_API_SLEEP_TIME
        self.public_api_request_per_min = virustotalconst.PUBLIC_API_REQUEST_PER_MIN

    def retrive_url_reports(self, urls_to_check):

        reports = []
        params = {'apikey': self.api_key}
        counter = 0
        i = 0
        url_lenght = len(urls_to_check)
        print('Scanning ' + str(url_lenght) + (' websites\nThis may take a while' if url_lenght > 1 else ' website'))

        for url_to_check in urls_to_check:
            try:
                params['resource'] = url_to_check
                if counter >= self.public_api_request_per_min: 
                    time.sleep(self.public_api_sleep_time) #reach limit 4 requests/minute
                    counter = 0
                i += 1
                print('Scanning...' + url_to_check + '('+ str(i)+ '/'+str(url_lenght)+')')
                response = requests.get(self.url_base, params=params)
                counter += 1

                if response.status_code == virustotalconst.PRODUCED_CODE:
                    json_response = response.json()
                    if json_response['response_code'] == 1:
                        reports.append(json_response)
                    else:
                        print(json_response['resource'] + ': ' +
                              json_response['verbose_msg'])
                elif response.status_code == virustotalconst.QUOTA_CODE:
                    print(
                        'Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
                    print('Sleep for ' + str(self.public_api_sleep_time) + ' sec..')
                    time.sleep(self.public_api_sleep_time)
                    counter = 0    
                elif response.status_code == virustotalconst.BAD_VALUES_CODE:
                    print(
                        'Received HTTP 400 response. Bad request can be caused by missing arguments or arguments with wrong values')
                elif response.status_code == virustotalconst.FORBIDDEN_CODE:
                    print(
                        'Received HTTP 403 response. Forbidden. You don''t have enough privileges to make the request.')

            except requests.exceptions.HTTPError as err:
                print(err)
            except requests.exceptions.ConnectTimeout as err:
                print('Connection timed out:' + str(err))
            except Exception:
                import traceback
                print('generic exception: ' + traceback.format_exc())
            
        return reports
