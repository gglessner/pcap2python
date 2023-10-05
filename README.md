# pcap2python
Turn a PCAP file into a Python3 script to replay application data

Similar to TCP replay; however, this code generates a standalone python script to replay application data.  This script supports replaying of multiple TCP connections.  
This script assumes that the client sends data first and the server responds to each message sent by the client.  If this is not your client-server communication model,
this probably won't be useful.

	Example:

		./pcap2py.py -f ./my_pcap_file.pcapng -s 1.1.1.1 -d 1.1.1.2 -p 1234 > output_script.py
		chmod +x ./output_script.py
