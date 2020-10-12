 """
 Author: JouKh 2020

 """
import errno
import requests

from .vt3base import VirusTotalAPI
from .vt3error import VirusTotalAPIError

class VirusTotalAPIAnalyses(VirusTotalAPI):
    """The retrieving information about analysis of the file or URL method are defined in the class.
       Methods:
          get_report(): Retrieve information about a file or URL analysis.
    """
    def get_repo(self,object_id):
        self._last_http_error = None
        self._last_result = None

        api_url = self.base_url + '/analyses/' + object_id

        try:
            response = requests.get(api_url, headers = self.headers,
                                    timeout = self.timeout, proxies = self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
