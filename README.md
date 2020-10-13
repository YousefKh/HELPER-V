# _    _ ______ _      _____  ______ _____     __      __
#| |  | |  ____| |    |  __ \|  ____|  __ \    \ \    / /
#| |__| | |__  | |    | |__) | |__  | |__) |____\ \  / / 
#|  __  |  __| | |    |  ___/|  __| |  _  /______\ \/ /  
#| |  | | |____| |____| |    | |____| | \ \       \  /   
#|_|  |_|______|______|_|    |______|_|  \_\       \/
Jou-Kh
VirusTotal API3


## Installation

```bash
pip3 install vtapi3
pip3 install requests
```

Before using the package from the command line, you must create an environment variable [vt_api_key] in which to place the value of the access key to the VirusTotal API functions

## Usage
###### Code

```python3
import hashlib
import requests
  ....
    try:
        vt_files = vtapi3.VirusTotalAPIFiles(api_key)
        result = vt_files.get_report(hash_id)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_files.get_last_http_error())
    ...
```
###### Example
`python3 helper-v.py -hr 033bd94b1168d7e4f0d644c3c95e35bf`
###### Output
```
Analysis report:
{
    "data": {
        "attributes": {
            "first_submission_date": 1251886094,
            "last_analysis_date": 1596672428,
            "last_analysis_results": {
                "ALYac": {
                    "category": "undetected",
                    "engine_name": "ALYac",
                    "engine_update": "20200806",
                    "engine_version": "1.1.1.5",
                    "method": "blacklist",
                    "result": null
                }
```
### Positional arguments
* resource - Object that you want to analyse in VirusTotal (file, URL, IP address or domain).
### Optional arguments
*[-h], [--help] - Show help message and exit
*[-hr], [--hash-report] - Getting a report on the results of analyzing a file by its hash (SHA256, SHA1 or MD5).
*..*[-uid], [--url-id] - Getting the identifier of the URL for further analysis.
*[-usr], [--url-scan-report] - Getting a report on the results of scanning a URL.
*[-uar], [--url-analyse-report] - Getting a report on the results of URL analysis.
*[-ipr], [--ip-report] - Getting a report on the results of IP address analysis.
*[-dr], [--domain-report] - Getting a report on the results of domain analysis.
