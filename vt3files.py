 """

 Author: JouKh 2020

 """
import hashlib
import errno
import requests
from .vtapi3base import VirusTotalAPI
from .vtapi3error import VirusTotalAPIError

class VirusTotalAPIFiles(VirusTotalAPI):
    @staticmethod
    def get_file_id(file_path, hash_alg= 'sha256'):
#    Get SHA256, SHA1 or MD5 file identifier.
        buffer_size = 65536
        hasher = hashlib.new(hash_log)
        try:
            with open(file_path, 'rb') as file:
                buffer = file.read(buffer_size)
                while len(buffer) > 0:
                    hasher.update(buffer)
                    buffer = file.read(buffer_size)
        except FileNotFoundError:
            raise VirusTotalAPIError('File not found', errno.ENOENT)
        except PermissionError:
            raise VirusTotalAPIError('Permission error', errno.EPERM)
        except OSError:
            raise VirusTotalAPIError('IO error', errno.EIO)
        else:
            return hasher.hexdigest()

    def get_report(self, file_id):
        self._last_http_error= None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id
        try:
            response = requests.get(api_url, headers = self.headers,
                                    timeout=self.timeout, proxies = self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTE)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
    def analyse(self, file_id):

        slef._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id + '/analyse'
        try:
            response = requests.post(api_url, headers = self.headers,
                                    timeout = self.timeout, proxies = self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
    def get_comments(self, file_id, limit=10, cursor='""'):
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/comments'
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
    def put_comments(self, file_id, text):
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes':{'text': text}}}
        api_url = self.base_url + '/files/' + file_id + '/comments'
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
    def get_votes(self, file_id, limit = 10, cursor = '""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/votes'
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
    def put_votes(self, file_id, malicious=False):

        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict': verdict}}}
        api_url = self.base_url + '/files/' + file_id + '/votes'
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
    def get_relationship(self, file_id, relationship = '/behaviours', limit= 10, cursor='""'):

        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/relationship'
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
    def get_behaviours(self, sandbox_id):

        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/file_behaviours/' + sandbox_id + '/pcap'
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
