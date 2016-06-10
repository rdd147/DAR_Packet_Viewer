# DAR_Packet_Viewer 

DARv3 is a network, packet based standard of accurately timestamped data, comparable to a PCAP file, however there is currently not many tools avaliable to look at packets of data. 

This is a packet viewer to decode and display the binary file data of the DARv3 standard for development and support engineers. It is meant to display all information contained in the currently viewed packet, with several widgets used to navigate the file and save data of interest.

This program comes with a sample development .dr3 file.

It includes: 

A large text widget - to show the decoded packet data 

Next and Previous Packet buttons - to navigate through adjacent packets in the file, 

A file offset entry widget - to navigate to the closest forward packet to the user offset

Dropdown DSID filter window - When the packet is a XML type packet, looks for all the DSID channel numbers in the XML packet and puts them in a selectable list. All widgets and buttons will only search for packets with the selected DSID of interest.

Save Packet to File button - Saves the current text decoded packet to a .txt file of the users choosing.

Percent (%) slider bar - Allows for quick navigation through the file.


Dependencies:

Requires python 2.7.9 and the enum module installed for the source to run
