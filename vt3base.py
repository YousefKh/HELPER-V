 """
 Author: JouKh 2020

 """
import requests

class VirusTotalAPI:
    """A base class for subclasses that implement methods for working with files, URLs, domain
       names, and IP addresses.
       Attributes:
          base_url: The base URL for sending requests (str).
          headers: Request header containing API key (dict).
          timeout: Server response timeout. A tuple that includes a timeout value for 'connect' and
             a timeout value for 'read'. If specify a single timeout value, it will be applied to
             both timeout 'connect' and timeout 'read'.
          proxies: The Protocol and the URL of the proxy server (dict).
          _version_api: VirusTotal API version (str).
          _last_http_error: HTTP status code of last operation (int).
          _last_result: Result of the last execution of a subclass method of this class.
       Constants: HTTP error codes constants.
       Methods:
         get_version_api(): Return the API version values.
         get_last_http_error(): Return the HTTP status code of last operation.
         get_last_result(): Return the result of executing methods of subclasses of this class.
    """
    HTTP_OK = requests.codes['ok']
    HTTP_BAD_REQUEST_ERROR = requests.codes['bad_request']
    HTTP_AUTHENTICATION_REQUEST_ERROR = requests.codes['unauthorized']
    HTTP_FORBIDDEN_ERROR = requests.codes['forbidden']
    HTTP_NOT_FOUND_ERROR = requests.codes['not_found']
    HTTP_ALREADY_EXSITS_ERROR = requests.codes['conflict']
    HTTP_QUATA_EXCEEDED_ERROR = requests.codes['too_many_requests']
    HTTP_TRANSIENT_ERROR = requests.codes['service_unavaliable']

    def __init__(self, api_key= None, timeout = None, proxies= None):
        self.base_url = 'https://developers.virustotal.com/v3.0/'
        self.headers =  {'x-apikey' : api_key}
        self.timeout = timeout
        self.proxies = proxies
        self._version_api = 'version 3'
        self._last_http_error = None
        self._last_result = None
    def get_version_api(self):

        return self._version_api
    def get_last_http_error(self):

        return self._last_http_error
    def get_last_result(self):

        return self._last_result
