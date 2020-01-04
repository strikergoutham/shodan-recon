'''

Script : shodan-recon

Description : shodan-recon is a cli python 3 based information gathering tool which helps to fetch useful information from shodan search engine.
It uses already existing Shodan API's and it requires the end user to possess API key.

Some of the current features :

>> query shodan search engine directly using queries/custom queries and fetch useful results and statistics.
>> automated on-demand scan service.
>> Pulls domain and subdomain information.
>> IP lookup.

use shodan-recon.py --help for detailed usage.

Author : Goutham Madhwaraj K B.
@barriersec.com


'''


import shodan
import argparse
import requests
import json
import time



parser = argparse.ArgumentParser()
MandatoryArgs = parser.add_argument_group('required Arguments')
MandatoryArgs.add_argument('-k', '--apiKey', help='API key of Shodan.', required=True)
parser.add_argument('-ip', "--host", help='host ip to lookup shodan.')
parser.add_argument('-s', "--query", help='use this option to search shodan for a particular query. ex : "product:Docker".')
parser.add_argument('-odip', "--ondemandscan", help='list of comma seperated IP for ondemand scan request.')
parser.add_argument('-dlurl', "--domainLookupURL", help='URL of the domain to fetch information. fetches the subdomains and DNS entry of the provided domain')


args = parser.parse_args()
if args.apiKey is None:
    parser.print_help()
    exit()
SHODAN_API_KEY = args.apiKey

api = shodan.Shodan(SHODAN_API_KEY)

BoolOnDemandScan = True
BoolIpLookup = True
BoolSearch = True
BooldomainLookupURL = True

if args.host is None:
    BoolIpLookup = False

if args.query is None:
    boolSearch = False

if args.ondemandscan is None:
    BoolOnDemandScan = False

if args.domainLookupURL is None:
    BooldomainLookupURL = False

querystring = {
        'key': SHODAN_API_KEY
    }
headers = {
        'Accept': 'application/json'
    }


def ondemandScan():
    odip = args.ondemandscan
    onDemandScanEndpoint = 'https://api.shodan.io/shodan/scan'

    data = {

        'ips': odip
    }
    response = requests.request(method='POST', url=onDemandScanEndpoint, headers=headers, params=querystring, data=data)
    JsonResponse = json.loads(response.text)
    if 'error' in JsonResponse:
       print(JsonResponse['error'])
    if 'id' in JsonResponse:
        print("request ID : ", JsonResponse['id'])
        print("Request submitted successfully.Remaining Credits left for on demand scan : " ,JsonResponse['credits_left'])
        print("checking scan status and waiting for scan to complete....")
        statusurl = "https://api.shodan.io/shodan/scan/"+JsonResponse['id']
        statusresp = requests.request(method='GET', url=statusurl, headers=headers,params=querystring)
        statusrespjson = json.loads(statusresp.text)
        if 'status' in statusrespjson:
            while statusrespjson['status'] != "DONE":
                time.sleep(5)
                print("checking scan status and waiting for scan to complete....")
                statusresp = requests.request(method='GET', url=statusurl, headers=headers,params=querystring)
                statusrespjson = json.loads(statusresp.text)
            print("SUCCESS!!!Use search query option to fetch the results or use download option to fetch! scan:",JsonResponse['id'])


def DomainInfo():

    dlurl = args.domainLookupURL
    domainLookUpURL = "https://api.shodan.io/dns/domain/"+dlurl
    domresp = requests.request(method='GET', url=domainLookUpURL, headers=headers, params=querystring)
    domrepjson = json.loads(domresp.text)
    if 'error' in domrepjson:
        print(domrepjson['error'])
    if 'domain' in domrepjson:
        print("Sub domain Details for domain ",domrepjson["domain"])
        print(domrepjson)
        count = len(domrepjson["data"])
        print("Number of Records: ",count)
        if count > 0:
            for i in range(0,count):
                print("SUB DOMAIN: ", domrepjson["data"][i]["subdomain"])
                print("Type of DNS record: ", domrepjson["data"][i]["type"])
                print("value: ", domrepjson["data"][i]["value"])
                print("Last Seen: ", domrepjson["data"][i]["last_seen"])
                print("..............................................................................................")

def searchQuery():

    searchQuery = args.query
    FACETS = [
        ('org',10),
        ('domain',10),
        ('port',10),
        ('asn',10),
        ('country', 10),
    ]

    FACET_TITLES = {
        'org': 'Top 10 Organizations',
        'domain': 'Top 10 Domains',
        'port': 'Top 10 Ports',
        'asn': 'Top 10 Autonomous Systems',
        'country': 'Top 10 Countries',
    }

    try:
            result = api.count(searchQuery, facets=FACETS)

            results = api.search(searchQuery)
            for facet in result['facets']:
                print(FACET_TITLES[facet])

                for term in result['facets'][facet]:
                    print('%s: %s' % (term['value'], term['count']))
                print(' ')
            print('Results found: {}'.format(results['total']))
            for resultMatch in results['matches']:
                    print('IP: {}'.format(resultMatch['ip_str']))
                    print('Port: {}'.format(resultMatch['port']))
                    print('')
    except shodan.APIError as e:
        print('Error: {}', format(e))


def LookupIP():

    try:
        hostIP = args.host
        host = api.host(hostIP)

        print("""
                IP: {}
                Organization: {}
                Operating System: {}
        """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

        for item in host['data']:
                print("""
                        Port: {}
                        Banner: {}
        
                """.format(item['port'], item['data']))

    except shodan.APIError as e:
        print('Error: {}', format(e))


if __name__ == "__main__":
    if BoolIpLookup is True:
        LookupIP()
    if BoolSearch is True:
        searchQuery()
    if BoolOnDemandScan is True:
        ondemandScan()
    if BooldomainLookupURL is True:
        DomainInfo()