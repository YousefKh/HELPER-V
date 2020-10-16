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
