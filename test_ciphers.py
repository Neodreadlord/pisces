#
# @Author = James Maguire
#   Date: August 2020
#       Final year project
#           The National College of Ireland
#               Supervisor: Vikas Sahni
#

import subprocess as sp
import sys

host = sys.argv[1]
port = sys.argv[2]

# scanning using sslscan for tls and ssl version and Heartbleed vulnerability

sp.Popen("pysslscan scan --scan=vuln.heartbleed --scan=server.preferred_ciphers "
         "--scan=server.ciphers --report=term:rating=ssllabs.2009e "
         "--ssl2 --ssl3 --tls10 --tls11 --tls12 " + host + ":" + port)
