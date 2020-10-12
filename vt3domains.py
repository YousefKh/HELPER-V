 """
 Author: JouKh 2020

 """
import errno
import requests

from .vt3base import VirusTotalAPI
from .vt3error import VirusTotalAPIError

class VirusTotalAPIDomains(VirusTotalAPI):

    def get_repo(self, domain):
        self._lasr_http_error = None
        self._last_result = None
        api_url = self.base_url + '/domains/' + domain
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
    def get_comments(self, domin, limit= 10, cursor = '""'):

        self._last_http_error= None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor' : cursor}
        api_url = self.base_url + '/domains/' + domain + '/comments/'
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
    def put_comments(self, domain, text):

        self._last_http_error = None
        self._last_result = None
        comments = {"data":{'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/domains/' + domain + '/comments'
        try:
            response = requests.post(api_url, headers = self.headers, json = comments,
                                    timeout = self.timeoutm, proxies = self.proxies)


    def get_relationship(self, domain, Relationship = '/resolutions', limit = 10, cursor = '""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
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

    def get_votes(self, domain, limit = 10, cursor= '""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/domains/' + domain + '/votes'
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
