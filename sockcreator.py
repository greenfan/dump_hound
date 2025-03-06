import re
from subprocess import Popen, PIPE

def sock_table():
    # Execute lsof using Popen
    lsof_data = Popen(
        ["lsof", "-i", "-n", "-P"],
        stdout=PIPE,
        stderr=PIPE,
        universal_newlines=True
    ).communicate()[0]

    sock_dicts = []

    # Split captured data into lines
    for line in lsof_data.splitlines():
        # Split line into parts
        parts = line.split()
        
        # Perform basic validation
        if len(parts) < 9:
            continue
        
        # Extract relevant fields: ensure parts cover required fields by index
        proc = parts[0]
        pid = parts[1]
        fd = parts[3]  # remember indexing from zero
        proto = parts[7]
        
        # Handle connection field and parse it
        connection = " ".join(parts[8:])

        # Using regex to parse the connection info
        # This assumes the format is: "source_ip:source_port->dest_ip:dest_port"
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)', connection)
        if not match:
            continue  # skip if line does not match expected format
        
        source, s_port, dest, d_port = match.groups()

        # Create dictionary entry
        sock_dict = {
            'proc': proc,
            'pid': pid,
            'fd': fd,
            'proto': proto,
            'source': source,
            's_port': int(s_port),  # ports should be integers
            'dest': dest,
            'd_port': int(d_port)   # ports should be integers
        }

        # Append the current entry to the list
        sock_dicts.append(sock_dict)

    return sock_dicts

# Example usage: Fetch and print the dictionary entries
sock_entries = sock_table()
for entry in sock_entries:
    print(entry)