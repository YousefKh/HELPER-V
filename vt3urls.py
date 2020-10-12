import base64
import hashlib
import errno
import requests
from .vt3base import VirusTotalAPI
from .vt3error import VirusTotalError

class VirusTotalAPIUrls(VirusTotalAPI):
    @staticmethod
    def get_url_id_sha256(url):
        return hashlib.sha256(url.encode()).hexdigest()
    def upload(self, url):
        self._last_http_error = None
        self._last_result = None
        data = {'url': url}
        api_url = self.base_url + '/urls'
        try:
            respone = requests.post(api_url, headers=self.headers, data = data,
                                    timeout = self.timeout, proxies = self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = respone.status_code
            self._last_result =respone.content
            return respone.content
    def get_report(self, url_id):

        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
    def analyse(self, url_id):

        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id + '/analyse'
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
    def get_comments(self, url_id, limit=10, cursor='""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + '/comments'
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
    def put_comments(self, url_id, text):

        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/urls/' + url_id + '/comments'
        try:
            response = requests.get(api_url, headers=self.headers, json=comments,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
    def get_votes(self, url_id, limit=10, cursor='""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + '/votes'
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
    def put_votes(self, url_id, malicious=False):

        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes':{'verdict':verdict}}}
        api_url = self.base_url + '/urls/' + url_id + '/votes'
        try:
            response = requests.get(api_url, headers=self.headers, json=votes,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
    def get_network_location(self, url_id):
        """Get the domain or IP address for a URL."""
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id + '/network_location'
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
    def get_relationship(self, url_id, relationship= '/last_serving_ip_address',
                        limit = 10, cursor = '""'):
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + relationship
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
