# -*- coding: utf-8 -*-
"""
Created on 12-Oct-2020

@author: JouKh
"""
import requests
import os
import json
import errno
import argparse
import vtapi3


def get_env_api_key():

    if 'vt_api_key' in os.environ:
        result = os.environ['vt_api_key']
    else:
        raise vtapi3.VirusTotalAPIError('API key environment error', errno.EINVAL)
    return result

def get_hash_report(hash_id, api_key):

    try:
        vt_files = vtapi3.VirusTotalAPIFiles(api_key)
        result = vt_files.get_report(hash_id)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_files.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_url_id_to_analyse(url, api_key):

    vt_urls = vtapi3.VirusTotalAPIUrls(api_key)

    try:
        result = vt_urls.upload(url)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            result = 'URL ID: ' + result['data']['id']
        else:
            result = 'HTTP error ' + str(vt_urls.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_url_scan_report(url, api_key):

    vt_urls = vtapi3.VirusTotalAPIUrls(api_key)

    try:
        result = vt_urls.upload(url)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            url_id = result['data']['id']
            vt_analyses = vtapi3.VirusTotalAPIAnalyses(api_key)
            result = vt_analyses.get_report(url_id)
            if vt_analyses.get_last_http_error() == vt_analyses.HTTP_OK:
                result = json.loads(result)
                result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
            else:
                result = 'HTTP error ' + str(vt_analyses.get_last_http_error())
        else:
            result = 'HTTP error ' + str(vt_urls.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_url_analyse_report(url, api_key):

    vt_urls = vtapi3.VirusTotalAPIUrls(api_key)

    try:
        url_id = vt_urls.get_url_id_base64(url)
        result = vt_urls.get_report(url_id)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_urls.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_ip_report(ip_address, api_key):

    try:
        vt_ip = vtapi3.VirusTotalAPIIPAddresses(api_key)
        result = vt_ip.get_report(ip_address)
        if vt_ip.get_last_http_error() == vt_ip.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_ip.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_domain_report(domain, api_key):

    try:
        vt_domain = vtapi3.VirusTotalAPIDomains(api_key)
        result = vt_domain.get_report(domain)
        if vt_domain.get_last_http_error() == vt_domain.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_domain.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def create_cmd_parser():
    parser = argparse.ArgumentParser(prog='vtapi3')
    parser.add_argument('resource',
                        help='Object that you want to analyse in VirusTotal (file, URL, IP address or domain)')
    parser.add_argument('-hr', '--hash-report', action='store_true', dest='hash_report',
                        help='Getting a report on the results of analyzing a file by its hash (SHA256, SHA1 or MD5)')
    parser.add_argument('-uid', '--url-id', action='store_true', dest='url_id',
                        help='Getting the identifier of the URL for further analysis')
    parser.add_argument('-usr', '--url-scan-report', action='store_true', dest='url_scan_report',
                        help='Getting a report on the results of scanning a URL')
    parser.add_argument('-uar', '--url-analyse-report', action='store_true', dest='url_analyse_report',
                        help='Getting a report on the results of URL analysis')
    parser.add_argument('-ipr', '--ip-report', action='store_true', dest='ip_report',
                        help='Getting a report on the results of IP address analysis')
    parser.add_argument('-dr', '--domain-report', action='store_true', dest='domain_report',
                        help='Getting a report on the results of domain analysis')
    return parser


def get_cmd_options(parser):
    return parser.parse_args()

def main(options):
    print('\nThe helper-v package Implement the VirusTotal service API Functions (V3).')
    print('\n Jou-Kh oct-2020 \n')
    try:
        api_key = get_env_api_key()
        if options.hash_report:
            result = get_hash_report(options.resource, api_key)

        elif options.url_id:
            result = get_url_id_to_analyse(options.resource, api_key)
        elif options.url_scan_report:
            result = get_url_scan_report(options.resource, api_key)
        elif options.url_analyse_report:
            result = get_url_analyse_report(options.resource, api_key)
        elif options.ip_report:
            result = get_ip_report(options.resource, api_key)
        elif options.domain_report:
            result = get_domain_report(options.resource, api_key)
        else:
            result = get_url_analyse_report(options.resource, api_key)
        return result

    except vtapi3.VirusTotalAPIError as err:
        return err

if __name__ == '__main__':
    print(main(get_cmd_options(create_cmd_parser())))
