 """
 Author: JouKh 2020

 """
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
