from scapy.arch.windows import get_windows_if_list

# Get a list of available network interfaces and their details
network_interfaces = get_windows_if_list()


# Print the interface names
print("Available network interfaces:")
for network_interface in network_interfaces:
    print ( (network_interface))
