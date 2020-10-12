 """
 Author: JouKh 2020

 """
import errno
import requests

from .vtapi3base import VirusTotalAPI
from .vtapi3error import VirusTotalAPIError

class VirusTotalAPIIPAddresses(VirusTotalAPI):
    def get_repo(self, ip_address):

        self._lasr_http_error = None
        self._last_result = None
        api_url = self.base_url + '/ip_addresses/' + ip_address
        try:
            response = requests.get(api_url, headers = self.headers,
                                    timeout = self.timeout, proxies= self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return respnse.content

    def get_comments(self, ip_address, limit= 10, cursor = '""'):

        self._last_http_error= None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor' : cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/comments/'
        try:
            response = requests.get(api_url, headers = self.headers, params = query_string,
                                    timeout = self.timeout, proxies = self.proxie)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return respnse.content
    def put_comments(self, ip_address, text):

        self._last_http_error = None
        self._last_result = None
        comments = {"data":{'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/comments'
        try:
            response = requests.post(api_url, headers = self.headers, json = comments,
                                     timeout = self.timeoutm, proxies = self.proxies)


    def get_relationship(self, ip_address, Relationship = '/resolutions', limit = 10, cursor = '""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + relationship
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_votes(self, ip_address, limit = 10, cursor= '""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/votes'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
         except requests.exceptions.Timeout:
             raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
         except requests.exceptions.ConnectionError:
             raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
         else:
             self._last_http_error = response.status_code
             self._last_result = response.content
             return response.content

    def put_votes(slef, domain, malicious = False):

        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict' : verdict}}}
        api_url = self.base_url + '/domains/' + domain + relationship
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
