import requests
import json
import urllib.parse
from dns import resolver
from spam_lists import SPAMHAUS_DBL
from spam_lists import SPAMHAUS_ZEN
from spam_lists import SURBL_MULTI
import argparse
import grequests


def getUsers(apiUrl, auth):
    commandUrl = apiUrl + 'CMD_API_SHOW_ALL_USERS'
    request = requests.get(commandUrl, auth=auth)
    output = urllib.parse.parse_qs(request.text)
    return output["list[]"]


def getDomains(apiUrl, users, auth):
    commandUrls = []
    results = {}
    for user in users:
        commandUrl = apiUrl + 'CMD_API_SHOW_USER_DOMAINS' + '?user=' + user
        commandUrls.append(commandUrl)
    requestStack = (grequests.get(commandUrl, auth=auth, timeout=2) for commandUrl in commandUrls)
    finalRequests = grequests.map(requestStack, size=5)
    for response in finalRequests:
        if response != '{}':
            user = urllib.parse.urlparse(response.url).query.replace("user=", "")
            output = urllib.parse.parse_qs(response.text)
            userDomains = []
            for domain in output:
                userDomains.append(domain)
                results[user] = userDomains
    data = []
    for user in results:
        for domain in results[user]:
            data.append({"{#USER}": user, "{#DOMAIN}": domain})
    output = json.dumps({'data': data}, indent=4)
    return output


def domainDetails(apiurl, user, domain, parameter, auth):
    querystring = {"user": user}
    command = "CMD_API_SHOW_USER_DOMAINS"
    domainUsers = []

    response = requests.request("GET", apiurl + command, auth=auth, params=querystring)
    parsed = urllib.parse.parse_qs(response.text)
    dat = json.dumps(parsed)
    data = json.loads(dat)
    for name in parsed:
        for details in data[name]:
            usersDetails = {
                "user": user,
                "domain": name,
                "details": {
                    "bandwidth used": str(details).split(":")[0],
                    "bandwidth limit": str(details).split(":")[1],
                    "disk usage for the domain": str(details).split(":")[2],
                    "log usage for the domain": str(details).split(":")[3],
                    "number of subdomains": str(details).split(":")[4],
                    "suspended": str(details).split(":")[5],
                    "quota": str(details).split(":")[6],
                    "ssl": str(details).split(":")[7],
                    "cgi": str(details).split(":")[8],
                    "php": str(details).split(":")[9]
                }
            }
            domainUsers.append(usersDetails)
    if user is not None and domain == "None" and parameter == "None":
        for item in domainUsers:
            print(item)
        return domainUsers

    elif user is not None and domain is not None and parameter == "None":
        domainUsers.clear()
        for name in data:
            for details in data[name]:
                if name == domain:
                    usersDetails = {
                        "user": user,
                        "domain": name,
                        "details": {
                            "bandwidth used": str(details).split(":")[0],
                        }
                    }
                    domainUsers.append(usersDetails)
        print(str(domainUsers))
        return domainUsers
    elif user is not None and domain is not None and parameter is not None:
        parsedData = json.loads(str(domainUsers).replace("\'", "\""))
        domainUsers.clear()
        for val in parsedData:
            if val['domain'] == domain:
                for item in val['details']:
                    if item == parameter:
                        print(parameter + ": " + val['details'][parameter])
        return domainUsers


def checkDomainResponseCode(domain):
    try:
        httpRequest = requests.request("GET", "http://" + domain, timeout=5)
    except:
        print(domain + " domain is unavailable!")
        httpRequest.close()
    else:
        print(domain + " is ok!")
        httpRequest.close()


resolver = resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8', 'ns1.qhosting.pl']
resolver.timeout = 1
resolver.lifetime = 1


def checkRecordA(domain):
    try:
        resp = resolver.query(domain, 'A')
    except:
        print("Brak danych")
        exit()
    else:
        for data in resp:
            return str(data)


def checkRecordMX(domain):
    addresses = ''
    try:
        resp = resolver.query(domain, 'MX')
    except:
        print("Brak danych")
        exit()
    else:
        for data in resp:
            recordMX = str(data)
            addresses += checkRecordA(str(recordMX)[3:-1]) + " "
        return addresses


def checkRecordNS(domain):
    addressdns = ''
    try:
        resp = resolver.query(domain, 'NS')
    except:
        print("Brak danych")
        exit()
    else:
        for data in resp:
            addressdns += str(data) + " "
        return addressdns


def checkIfDomainIsRegistered(domain, recordtype):
    try:
        if recordtype == 'A':
            print(checkRecordA(domain))
        elif recordtype == 'MX':
            print(checkRecordMX(domain))
        elif recordtype == 'NS':
            print(checkRecordNS(domain))
    except:
        exit()


def checkIfDomainIsOnBlackList(domain):
    if SPAMHAUS_DBL.lookup(domain):
        print(domain + " is on SPAMHAUS_DBL blacklist!")
    elif SPAMHAUS_ZEN.lookup(domain):
        print(domain + " is on SPAMHAUS_ZEN blacklist!")
    elif SURBL_MULTI.lookup(domain):
        print(domain + " is on SURBL_MULTI blacklist!")
    else:
        print(domain + " is not on a blacklist!")


class switch(object):
    value = None

    def __new__(class_, value):
        class_.value = value
        return True


def case(*args):
    return any((arg == switch.value for arg in args))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', help='user')
    parser.add_argument('-d', '--domain', help='domain')
    parser.add_argument('-p', '--param', help='search parameter')
    parser.add_argument('-m', '--method', help='method name to call')
    parser.add_argument('-url', '--apiurl', help='api url')
    parser.add_argument('-l', '--login', help='login')
    parser.add_argument('-ps', '--password', help='password')
    args = parser.parse_args()

    user = str(args.user).strip()
    domain = str(args.domain).strip()
    parameter = str(args.param).strip()
    method = str(args.method).strip()
    url = str(args.apiurl).strip()
    login = str(args.login).strip()
    password = str(args.password).strip()
    auth = (login, password)
    while switch(method):
        if case('checkresponse'):
            checkDomainResponseCode(domain)
            break
        if case('checkifregistered'):
            checkIfDomainIsRegistered(domain, parameter)
            break
        if case('checkifonblacklist'):
            checkIfDomainIsOnBlackList(domain)
            break
        if case('domaindetails'):
            domainDetails(url, user, domain, parameter, auth)
            break
        if case('allusers'):
            print(getUsers(url, auth))
            break
        if case('showdomains'):
            users = getUsers(url, auth)
            print(getDomains(url, users, auth))
            break
        print('To run script use command: '
              'python <scriptname.py> --method<method to call> -parameter<method argument>'
              '\nAvailable parameters: '
              '\n -u, --user, help=\'user\''
              '\n -d, --domain, help=\'domain\''
              '\n -p, --param, help=\'search parameter\''
              '\n -m, --method, help=\'method name to call\''
              '\n -url, --apiurl, help= \'api url\''
              '\n -l, --login, help= \'login\''
              '\n -ps, --password, help= \'password\''
              '\nAvailable methods to call: '
              '\n\tgetUsers(apiUrl) - use --method allusers -url apiurl -l login -ps password'
              '\n\tcheckDomainResponseCode(domain) - use --method checkresponse --domain domain'
              '\n\tcheckIfDomainIsRegistered(domain, recordType) '
              '\t\t- use --method checkifregistered --domain domain --parameter recordType'
              '\n\tcheckIfDomainIsOnBlackList(domain) - use --method checkifonblacklist --domain domain'
              '\n\tgetDomains(apiUrl, users) - use --method showdomains -url apiurl -l login -ps password'
              '\n\tdomainDetails(user, domain, parameter - use --method domaindetails '
              '--user user --domain domain --param parameter -url apiurl -l login -ps password')
        break
