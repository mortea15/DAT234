import argparse
import os
import subprocess

parser = argparse.ArgumentParser()  # Create an argumentparser

parser.add_argument("-f", "--filename", dest="filename", default="livehack.txt", help="Path to file")  # Add arguments
parser.add_argument("-sp", "--startport", dest="starting_port", default="0", help="A port to check from, e.g. 58239")
parser.add_argument("-ep", "--endport", dest="ending_port", default="0", help="A port to check to, e.g. 62489")

args = parser.parse_args()  # Parse the args and store them in the list args

lines = []  # List to contain the lines in the txt file

# Username
usernames = []  # List of unique usernames
username_count = {}  # Dict counting number of occurrences of a username
username_dict = {}  # Dict containing the hash(username) and username as a key value set

# IP addresses
ips = []  # List of unique IPs
ips_dict = {}  # Dict of IPs (using dict to be able to store ports as well, and since same IPs might use different ports)
ip_count = {}  # Dict counting the number of occurrences of an IP address
attacking_ips_ports = []

with open(args.filename) as file:  # Open the file
    for line in file:  # For each line
        line = line.strip()  # Strip it
        lines.append(line)  # Append the line to the list


def find_usernames(target):
    line_list = target.split()  # Split the line into a list of words
    try:
        user = line_list[
            line_list.index("user") + 1]  # In line_list, search for the word "user" and append 1 to find the username
        if user not in usernames:  # Check that the name is not already in the list of usernames
            usernames.append(user)  # Add it to the list if it's not
            username_count[user] = 1  # Add the user to the dict with a value of 1
            username_dict[hash(user)] = user
        else:
            username_count[user] += 1  # User has already been added to the dict, so increment the value by 1
    except Exception as e:
        pass
        # print(e)


def find_ips(target):
    line_list = target.split()  # Split the line into a list of words
    try:
        # In line_list, search for the word "from" and append 1 to find the IP
        ip = line_list[line_list.index("from") + 1]
        # In line_list, search for the word "port" and append 1 to find the port
        port = line_list[line_list.index("port") + 1]

        if ip not in ips:  # Check that the name is not already in the list of IP addresses
            ips.append(ip)  # Add the IP to the list of unique IP addresses
            ip_count[ip] = 1  # Add the IP to the dict of occurrences with a value of 1
            ips_dict[ip] = {port}  # Add it to the dict with the port used
        else:
            ip_count[ip] += 1  # IP address has already been added to the dict, so increment the value by 1
            ips_dict[ip].add(port)  # Add the port to the already existing entry, holding a set of ports used
    except Exception as e:
        pass
        # print(e)  # The words we tried to index did not exist on this line


def find_ips_in_range(starting_port, ending_port):  # Find the IPs with ports in the specified port range
    for key, value in ips_dict.items():  # Go through each key, value pair in the dict of ips
        for port in set(value):  # Go through each port in the set value

            # The solution below worked, but also added a few ports that were out of range for some reason
            # if starting_port <= port <= ending_port:
            if int(port) in range(int(starting_port), int(ending_port)):  # Check if the port is within the range
                attacking_ips_ports.append(key + ":" + str(port))  # Add the IP and port to the list of attackers


def check_already_pinged_ip(ip):  # Check if an IP has been pinged earlier
    pinged = False
    try:
        with open("ip_responses.txt") as file:  # Open the file containing the pinged IPs
            for line in file:  # For each line
                line = line.strip()  # Strip it
                if ip in line:  # If the line contains the given IP
                    if int(line.replace(ip + " ", "")) == 0:  # Check if the status is 0 (alive)
                        pinged = True  # Flag it as pinged
                        break  # End the loop
                else:  # The IP is not in the line
                    pinged = False  # Flag it as not pinged
    except FileNotFoundError:  # File does not exist
        pinged = False

    return pinged


def ping_ips():
    for ip in ips:
        if check_already_pinged_ip(ip):  # First we'll check if it has been pinged previously.
            print(ip + " has already been pinged. It was up")

        else:  # If it hasn't been pinged before, or did not respond the last time, it will be pinged again
            with open("ip_responses.txt", "a") as f:  # The file to write results to)
                with open(os.devnull, 'w') as DEVNULL:
                    try:
                        subprocess.check_call(
                            ['ping', '-n', '1', ip],
                            stdout=DEVNULL,  # Suppress the output
                            stderr=DEVNULL
                        )
                        result = 0  # Alive
                        if check_file_for_ip(ip):
                            continue
                        else:
                            f.write(ip + " " + str(result) + "\n")  # Write the ip and result to the file
                        print(ip + " was alive")
                    except subprocess.CalledProcessError:  # Host did not respond
                        result = 1  # Dead
                        if check_file_for_ip(ip):
                            continue
                        else:
                            f.write(ip + " " + str(result) + "\n")  # Write the ip and result to the file
                        print(ip + " was dead")


def check_file_for_ip(ip):
    exists = False
    with open("ip_responses.txt", "r") as f:
        for line in f:
            if ip in line:
                exists = True
                break
            else:
                exists = False

    return exists


for line in lines:  # For each line in the list of lines
    find_usernames(line)
    find_ips(line)

if int(args.starting_port) & int(args.ending_port) != 0:  # Only run the range-specific method if the user requested it
    find_ips_in_range(args.starting_port, args.ending_port)

print("\n\n")
print("USERNAME INFO")
print("_______________________________________________________________________________________________________________")
print("EACH USERNAME'S NUMBER OF OCCURRENCES")
print(username_count)
print("_______________________________________________________________________________________________________________")
print("LIST OF UNIQUE USERNAMES")
print(usernames)
print("_______________________________________________________________________________________________________________")
print("HASH DICT OF USERNAMES")
print(username_dict)

print("\n\n")
print("IP ADDRESS INFO")
print("_______________________________________________________________________________________________________________")
print("EACH IP'S NUMBER OF OCCURRENCES")
print(ip_count)
print("_______________________________________________________________________________________________________________")
print("LIST OF UNIQUE IP ADDRESSES")
print(ips)
print("_______________________________________________________________________________________________________________")
print("LIST OF IP ADDRESSES WITH PORTS USED")
print(ips_dict)

if int(args.starting_port) & int(args.ending_port) != 0:
    print(
        "_______________________________________________________________________________________________________________")
    print("IPs OF ATTACKERS WITH PORTS IN SPECIFIED RANGE")
    print(attacking_ips_ports)

print("_______________________________________________________________________________________________________________")
print("PINGING " + str(len(ips)) + " IP addresses")
ping_ips()
