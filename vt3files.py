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
