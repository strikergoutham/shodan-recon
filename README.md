# shodan-recon
shodan-recon is a cli python 3 based information gathering tool which helps to fetch useful information from shodan search engine. It uses already existing Shodan API's and it requires the end user to possess shodan API key.

basic usage :

python shodan-recon.py --help  << gives quick overview of the available options.

usage: shodan-recon.py [-h] -k APIKEY [-ip HOST] [-s QUERY]
                       [-odip ONDEMANDSCAN] [-dlurl DOMAINLOOKUPURL]

Shodan API Key should be given mandatorily.


search shodan using a custom query,fetch results and statistics:

python shodan-recon.py -k <API-Key> -s "product:Docker"
  
  
lookup an IP for details :

python shodan-recon.py -k <API-Key> -ip <IP>
  

Initiate an on demand scan for IP/set of IP's(comma seperated) :

python shodan-recon.py -k <API-Key> -odip <IP/IP's>
  
 
 fetch domain information and subdomain details of a domain :
 
 python shodan-recon.py -k <API-Key> -dlurl <example.com>
 
 
