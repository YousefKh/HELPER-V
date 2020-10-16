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
