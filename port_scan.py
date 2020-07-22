import socket
import subprocess
import sys
from datetime import datetime

print("-" * 60)
print("PORT SCAN TARGET: " + sys.argv[1])
print("-" * 60)

# clearing screen
subprocess.call('cls', shell = True)

# taking supplied input of URL and retrieving sockets

url = sys.argv[1]
Punconverted = sys.argv[2]
a, b = Punconverted.split('-')
ps = int(a)
pe = int(b)

remoteServerIP = socket.gethostbyname(url)


# banner
print("-" * 60)
print("Please wait, scanning remote host", remoteServerIP)
print("-" * 60)

# Check the time the scan started
time1 = datetime.now()

# Using range function to specify ports. We are using (1-10), error handling also
try:
    for port in range(ps, pe):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))

        if result == 0:
            print("Port {}:    Open".format(port))
            sock.close()
        else:
            print("Port {}:    Closed".format(port))

except KeyboardInterrupt:
    print("Port {}:    Open".format(port))
    print("You cancelled the scan")
    sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved. Exiting scan")
    sys.exit()

except socket.error:
    print("Couldn't connect to server")
    sys.exit()

# Check time again
time2 = datetime.now()

# Calculate time difference to workout run time
total_time = time2 - time1

# print to screen
print("Scanning completed in: ", total_time)
