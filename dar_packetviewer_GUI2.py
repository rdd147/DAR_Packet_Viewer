#!/usr/bin/python

from Tkinter import *
import tkFileDialog
import sys
import struct
import re
import os
import tarfile
import binascii
import time
from enum import Enum
from lxml import etree

class packettype(Enum):
    XML = 1  # implemented, will need bigger feature set
    PCM = 2  # implemented
    MNPCM = 3  # implemented
    A429 = 4  # implemented
    MPEG2 = 5
    MPEG4 = 6
    H264 = 7
    JPEG2000 = 8
    Bayer = 9
    RGB = 10
    RS232 = 11
    Status = 12
    Event = 13
    Audio = 14
    A664 = 15
    HFCI = 16
    MIL1553 = 17    #implemented
    CAN = 18
    ENETUDP = 19
    ENETTCP = 20
    ENETMAC = 21
    ENETIP = 22
    Unknown = 23


class window(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        #self.iconbitmap(default='iconLogo100.ico')
        self.initalize()
        return

    def initalize(self):
        self.parent.title("DARv3 Packet Viewer")
        # self.grid(row=0, column=0, columnspan=30)
        self.pack(fill=BOTH, expand=1)
        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)
        fileMenu = Menu(menubar, tearoff=False)
        file = fileMenu.add_command(label="Open", command=self.onOpen)
        file = fileMenu.add_command(label="Quit", command=self.quit)
        menubar.add_cascade(label="File", menu=fileMenu)
        self.txt = Text(self, height=60, width=200)
        self.scroll = Scrollbar(self)
        self.scroll.grid(row=2, column=5, sticky=E + N + S)
        self.scroll.config(command=self.txt.yview)
        self.txt.config(yscrollcommand=self.scroll.set)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(2, weight=1)
        self.txt.grid(row=0, column=0, columnspan=6, rowspan=4, sticky=N + S + E + W)
        # self.txt.pack(fill=BOTH, expand=1)
        self.button2 = Button(self, text="Previous Packet",
                              state=DISABLED)  # define and place widgets as disabled, enable later on
        self.button2.grid(row=5, column=0, sticky=W)
        # self.button2.pack(side=LEFT)
        self.button = Button(self, text="Next Packet", state=DISABLED)
        self.button.grid(row=5, column=1, sticky=W)
        # self.button.pack(side=LEFT)
        self.dropdown = Menubutton(self, text='DSID Filter', state=DISABLED)
        self.dropdown.grid(row=6, column=0, sticky=W)
        # self.dropdown.pack(side=BOTTOM , fill=Y)
        self.entry = Entry(self, width=20, state=DISABLED)
        self.entry.grid(row=5, column=5, sticky=E)
        # self.entry.pack(side=RIGHT, fill=Y)
        self.offset = Button(self, text="Go To Offset (hex)", state=DISABLED)
        self.offset.grid(row=5, column=4)
        # self.offset.pack(side=RIGHT)
        self.export = Button(self, text="Save Current Packet to File", state=DISABLED)
        self.export.grid(row=5, column=2)
        # self.export.pack(side=BOTTOM)
        self.slider = Scale(self, label='Position (%)', orient=HORIZONTAL, state=DISABLED, length=500)
        self.slider.grid(row=6, column=2)

    def setpreviousoffset(self, value):
        self.prevoffset = value

    def getpreviousoffset(self):
        return self.prevoffset

    def setcurrentbuf(self, buf):
        self.currentbuf = buf

    def returncurrentbuf(self):
        return self.currentbuf

    def set_current_DSID_filter(self, DSID):
        self.DSIDfilter = DSID
        if DSID == None:
            self.dropdown.configure(text='ALL')
        else:
            self.dropdown.configure(text=DSID)
            # print self.DSIDfilter

    def get_current_DSID_filter(self):
        return self.DSIDfilter

    def exportcurrentpacket(self):
        buf = self.returncurrentbuf()
        ftypes = [('Text file', '*.txt')]
        output = tkFileDialog.asksaveasfile(mode='w', filetypes=ftypes, defaultextension=".txt")
        if output is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        output.write(buf)
        output.close()

    def slider_position_goto(self, file):
        print self.slider.get()
        position = self.slider.get()
        if position == 0:
            offset_to_goto = 0
            print offset_to_goto
        else:
            offset_to_goto = int(os.fstat(file.fileno()).st_size *((self.slider.get()*.01)))-1
            print offset_to_goto
        if position == 100:
            file.seek(offset_to_goto)
            self.setpreviousoffset(None)
            self.seekpacketsbackwards(file)
        else:
            file.seek(offset_to_goto)
            EOFtest = file.read(1)
            if not EOFtest:
                return
            else:
                file.seek(offset_to_goto)
            self.seekpacketforward(file)

        return

    def goto_offset(self, file):
        offsetgoto = self.entry.get()
        nonhex = int(offsetgoto, 16)  # HEX input
        file.seek(nonhex)
        EOFtest = file.read(1)
        if not EOFtest:
            return
        else:
            file.seek(nonhex)
        self.seekpacketforward(file)

    def nextpacket(self, file):
        self.txt.delete(1.0, END)
        test = file.tell()
        self.setpreviousoffset(file.tell())
        packet_DSID, packet_type, text, allDSIDs = decode_header(file)
        print self.get_current_DSID_filter()
        if self.get_current_DSID_filter() != None and (str(packet_DSID) != self.get_current_DSID_filter()): # check for no filter case
            print self.get_current_DSID_filter()
            filtermatch = False
            while not filtermatch:
                filtermatch = self.DSIDcheck(file)
                if file.tell() == os.fstat(file.fileno()).st_size:
                    return
            packet_DSID, packet_type, text, allDSIDs = decode_header(file)
        self.txt.insert(END, text)
        self.setcurrentbuf(text)
        print "click!"

    def DSIDcheck(self, file):
        returnoffset = file.tell()
        header = file.read(20)  # read the 20 byte header
        DARtype = struct.unpack('!B', header[1:2])[0]
        packetlength = struct.unpack('!H', header[2:4])[0]
        packetlength = packetlength * 4
        datalength = packetlength - 20
        DSID = struct.unpack('!I', header[8:12])[0]
        if str(DSID) == self.get_current_DSID_filter():
            file.seek(returnoffset)
            return True
        else:
            file.seek(file.tell() + datalength)
            return False

    def previouspacket(self, file, previouspointer):
        self.txt.delete(1.0, END)
        file.seek(previouspointer)
        packet_DSID, packet_type, text, allDSIDs = decode_header(file)
        self.txt.insert(END, text)
        self.setcurrentbuf(text)
        print "click!"

    def testDARpacket(self, file, goodsync, returnoffset):
        header = file.read(20)  # read the 20 byte header
        DARtype = struct.unpack('!B', header[1:2])[0]
        DARsync = struct.unpack('!B', header[0:1])[0]
        packetlength = struct.unpack('!H', header[2:4])[0]
        packetlength = packetlength * 4
        datalength = packetlength - 20
        DSID = struct.unpack('!I', header[8:12])[0]
        mcastbyte1 = struct.unpack('!B', header[12:13])[0]
        if self.get_current_DSID_filter() != None:  # check for no filter case
            if str(DSID) != self.get_current_DSID_filter():
                return False, 0xff, 0xff # ff's mean  we do not know what these values should be
        if DSID > 1000 or mcastbyte1 < 224 or mcastbyte1 > 239: #check to qualify more 'random' data as good, to ensure the random data does not randomly find a good packet
            return False, 0xff, 0xff # ff's mean we do not know what these values should be
        file.seek(file.tell()-20)
        for x in range(0, 4):
            header = file.read(20)# read the 20 byte header
            if header == '':
                file.seek(returnoffset)
                return True, DSID, DARtype
            DARsync = struct.unpack('!B', header[0:1])[0]  # read 20 byte DAR header into own variables
            packetlength = struct.unpack('!H', header[2:4])[0]
            packetlength = packetlength * 4
            datalength = packetlength - 20
            DSID = struct.unpack('!I', header[8:12])[0]
            mcastbyte1 = struct.unpack('!B', header[12:13])[0]
            if DSID > 1000 or mcastbyte1 < 224 or mcastbyte1 > 239:  # check to qualify more 'random' data as good, to ensure the random data does not randomly find a good packet
                return False, 0xff, 0xff # ff's mean we do not know what these values should be
            # handle end of file case
            if DARsync != 0x35:
                file.seek(returnoffset)
                return False, 0xff, 0xff # ff's mean we do not know what these values should be
            print file.tell()
            file.seek(file.tell() + datalength)
        file.seek(returnoffset)
        return True, DSID, DARtype

    def seekpacketsbackwards(self, file):
        chunksize = 1024  # set chunk of data to be read
        goback = self.getpreviousoffset()  # go back to beginning of packet
        if goback == 0: # beginning of file case
            return
        if goback == None:
            goback = os.fstat(file.fileno()).st_size - chunksize
        file.seek(goback)
        currentoffset = file.tell()
        startoffset = file.tell()
        goodsync = False
        #list_to_seek = list(range(file.tell(), 0, -chunksize))
        #print list_to_seek
        if file.tell() - chunksize <= 0:
            file.seek(0)
        else:
            file.seek(file.tell()-chunksize)
        for pos in range(file.tell(), 0, -chunksize):
            file.seek(pos)
            whatsgoingon = file.tell()
            chunk = binascii.hexlify(file.read(chunksize))
            start_point_for_offset = file.tell()
            found = [m.start() for m in re.finditer('35', chunk)]  # regular expression search hex string chunk for 35 string and return list of indexes of all occurences
            found.sort(reverse=True)
            for index in found:  # loop over all indexes to check if it is the start of a packet
                if index % 2 == 0:  # if the index is not an even number, it is not a real instance. The string search is nibble by nibble, but in DAR, the lowest unit is a byte
                    checkoffset = start_point_for_offset - (len(chunk) / 2) + (index / 2)   # make file offset of exact instance, remembering to divide the index by 2, since it is addressed in nibbles, not bytes
                    file.seek(checkoffset)  # go to exact offset of area to check
                    goodsync, DSID, DARtype = self.testDARpacket(file, goodsync, checkoffset)  # call a test to check if the DAR packet is real
                    if goodsync == True and (DARtype != 0xf1 or file.tell() == 0):
                        print file.tell()
                        print checkoffset
                        self.nextpacket(file)
                        return
                    else:
                        if DARtype == 0xf1 or file.tell() == 0:
                            file.seek(0)
                            self.nextpacket(file)
                            return
                        file.seek(start_point_for_offset)

    def seekpacketforward(self, file):
        # need EOF test here
        currentoffset = file.tell()
        goodsync = False
        chunksize = 1024000 #set chunk of data to be read
        while True:
        #while range(0,1):
            chunk = file.read(chunksize) # read chunk of data
            currentoffset = file.tell() #update current file offset
            if chunk == '': #check for EOF, abort function if found
                return
            chunk = binascii.b2a_hex(chunk) #bring binary string over to hex string to be processed
            #print chunk #debugging print
            #for m in re.finditer('35', chunk):
                #m += 1
            found = [m.start() for m in re.finditer('35', chunk)]   #regular expression search hex string chunk for 35 string and return list of indexes of all occurences
            for index in found: #loop over all indexes to check if it is the start of a packet
                if index % 2 == 0:  #if the index is not an even number, it is not a real instance. The string search is nibble by nibble, but in DAR, the lowest unit is a byte
                    checkoffset = file.tell() - (len(chunk)/2) + (index/2)   #make file offset of exact instance, remembering to divide the index by 2, since it is addressed in nibbles, not bytes
                    file.seek(checkoffset)  #go to exact offset of area to check
                    goodsync, DSID, DARtype = self.testDARpacket(file, goodsync, checkoffset) #call a test to check if the DAR packet is real
                    if goodsync == True and (DARtype != 0xf1 or file.tell() == 0):
                        print 'YOU ARE THE MAN!!!'
                        print file.tell()
                        print checkoffset
                        self.nextpacket(file)
                        return
                    else:
                        file.seek(currentoffset)
            file.seek(currentoffset)
            #print found

    def onOpen(self):
        ftypes = [('DARv3', '*.dr3'), ('All files', '*')]
        dlg = tkFileDialog.Open(self, filetypes=ftypes)
        fl = dlg.show()

        if fl != '':
            self.parent.title("DARv3 Packet Viewer " + fl)
            text, file = self.readFile(fl)
            if self.txt.get != '':
                self.txt.delete(1.0, END)
            self.txt.insert(END, text)

    def readFile(self, filename):
        file = open(filename, 'rb')  # open file to view packets
        current_DSID, packet_type, buf, allDSIDs = decode_header(file)
        picks = Menu(self.dropdown, tearoff=False)
        self.dropdown.config(menu=picks, state=NORMAL)
        self.set_current_DSID_filter(None)
        picks.add_command(label='All', command=lambda: self.set_current_DSID_filter(None))
        for DSID in allDSIDs:
            picks.add_command(label=DSID, command=lambda DSID=DSID:self.set_current_DSID_filter(DSID))
            print self.get_current_DSID_filter()
        self.setcurrentbuf(buf)
        self.button.config(state=NORMAL, command=lambda: self.nextpacket(file))
        self.button2.config(state=NORMAL, command=lambda: self.seekpacketsbackwards(file))
        vcmd = (self.register(self.onvalidate),
                '%d', '%i', '%P')
        self.entry.config(state=NORMAL, validate="key", validatecommand=vcmd)
        # self.entry.bind('<KeyPress>', self.keyPress)
        self.offset.config(state=NORMAL, command=lambda: self.goto_offset(file))
        self.export.config(state=NORMAL, command=lambda: self.exportcurrentpacket())
        self.slider.config(state=NORMAL)
        for multi_buttons in ['<ButtonRelease-1>','<ButtonRelease-2>','<ButtonRelease-3>']:
            self.slider.bind(multi_buttons, lambda _: self.slider_position_goto(file))
        return buf, file

    def onvalidate(self, d, i, P):
        hexchars = (
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b', 'c', 'd', 'e', 'f')
        if d == '0':  # no need to validate on delete events
            return True
        if d == '1':  # validate on insertion events
            if P[int(i)] in hexchars:  # look at new string P with the new character I and check if it is in hexchars
                return True
            else:
                self.bell()
                return False


def decode_header(file):  # determines what data is in the following packet
    currentpacketoffset = file.tell()
    print 'current packet = ' + str(currentpacketoffset)
    header = file.read(20)  # read the 20 byte header
    DARsync = struct.unpack('!B', header[0:1])[0]  # read 20 byte DAR header into own variables
    DARtype = struct.unpack('!B', header[1:2])[0]
    packetlength = struct.unpack('!H', header[2:4])[0]
    packetlength = packetlength * 4
    datalength = packetlength - 20
    configcount = struct.unpack('!B', header[4:5])[0]
    flags = struct.unpack('!B', header[5:6])[0]
    sequence_number = struct.unpack('!H', header[6:8])[0]
    DSID = struct.unpack('!I', header[8:12])[0]
    mcastbyte1 = struct.unpack('!B', header[12:13])[0]
    mcastbyte2 = struct.unpack('!B', header[13:14])[0]
    mcastbyte3 = struct.unpack('!B', header[14:15])[0]
    mcastbyte4 = struct.unpack('!B', header[15:16])[0]
    secondstime = struct.unpack('!I', header[16:20])[0]
    formattedseconds = time.strftime('%m/%d/%Y %H:%M:%S',
                                     time.gmtime(secondstime))  # convert seconds only 1588 time into julien date
    if DARsync != 0x35:  # check for DAR sync on first byte of header
        print 'Packet sync not found where expected!'
        print 'Stopped at offset :', (file.tell() - 20)
        print DARsync
        sys.exit(3)
    # total_header_data = [int(currentpacketoffset), DARsync, DARtype, packetlength, datalength, configcount, flags, sequence_number, DSID, mcastbyte1, mcastbyte2, mcastbyte3, mcastbyte4, secondstime, formattedseconds]
    rtc_flag = flags & 0x04
    fragmentation_flag = flags & 0x02
    time_lock_flag = flags & 0x01
    if rtc_flag == 0:  # set flags to no and yes string instead of 0 and 1
        rtc_flag = 'No'
    else:
        rtc_flag = 'Yes'
    if fragmentation_flag == 0:
        fragmentation_flag = 'No'
    else:
        fragmentation_flag = 'Yes'
    if time_lock_flag == 0:
        time_lock_flag = 'No'
    else:
        time_lock_flag = 'Yes'
    print flags
    print rtc_flag, fragmentation_flag, time_lock_flag
    total_header_data = {'currentpacketoffset': int(currentpacketoffset), 'DARsync': DARsync, 'DARtype': DARtype,
                         'packetlength': packetlength, 'datalength': datalength, 'configcount': configcount,
                         'rtc_flag': rtc_flag, 'fragmentation_flag': fragmentation_flag,
                         'time_lock_flag': time_lock_flag, 'sequence_number': sequence_number, 'DSID': DSID,
                         'mcastbyte1': mcastbyte1, 'mcastbyte2': mcastbyte2, 'mcastbyte3': mcastbyte3,
                         'mcastbyte4': mcastbyte4, 'secondstime': secondstime, 'formattedseconds': formattedseconds}
    print total_header_data
    print total_header_data.get('currentpacketoffset')
    # packetnum = packetnum + 1
    # Write all header data in a list, to be passed to form PCM decode
    packet_type = what_packet_is_it(DARtype)
    header_string = form_header(total_header_data)
    buf = ''
    allDSIDs = []
    if packet_type.name == 'PCM' or packet_type.name == 'MNPCM':  # check for packet types
        total_segment_data = decode_PCM_packet(file, datalength)  # get all segment headers and data in dict form
        # print packetnum
        print 'STOPPED HERE : ' + str(file.tell())
        buf = formPCMdisplay(header_string, total_segment_data, secondstime, formattedseconds,
                             file)  # pass header_string and segment data to this function, to form the PCM display
    elif packet_type.name == 'XML':
        buf, allDSIDs = decode_XML_packet(file, datalength)
    elif packet_type.name == 'A429':
        total_segment_data = decode_429_packet(file, datalength)
        buf = formA429display(header_string, secondstime, formattedseconds, total_segment_data, file)
    elif packet_type.name == 'MIL1553':
        total_segment_data = decode_1553_packet(file, datalength)
        buf = form1553display(header_string, secondstime, formattedseconds, total_segment_data, file)
    else:
        buf = unknown(file, header_string, total_header_data)
    rawheader = ''.join(x.encode('hex') for x in header)  # packet header printout for debugging purposes
    print rawheader
    return DSID, packet_type, buf, allDSIDs


def form_header(total_header_data):
    displaydata = []  # make list of strings to form packet output
    displaydata.append('=====================================================================')
    displaydata.append(
        '{:<24}'.format('Offset      :  ' + str(hex(total_header_data.get('currentpacketoffset'))[2:]).zfill(16)))
    displaydata.append('{:<24}'.format('DSID        :  ' + str(total_header_data.get('DSID'))) + '{:<24}'.format(
        'Sync       :  ' + str(hex(total_header_data.get('DARsync')))) + '{:<24}'.format(
        'Pkt Len     :  ' + str(total_header_data.get('packetlength'))))
    displaydata.append('{:<24}'.format('Conf Cnt    :  ' + str(total_header_data.get('configcount'))) + '{:<24}'.format(
        'Seq Num    :  ' + str(total_header_data.get('sequence_number'))) + '{:<24}'.format(
        'Mcast Addr  :  ' + str(total_header_data.get('mcastbyte1')) + '.' + str(
            total_header_data.get('mcastbyte2')) + '.' + str(total_header_data.get('mcastbyte3')) + '.' + str(
            total_header_data.get('mcastbyte4'))))
    displaydata.append('{:<24}'.format('RTC tstmp   :  ' + total_header_data.get('rtc_flag')) + '{:<24}'.format(
        'Fgmntation :  ' + total_header_data.get('fragmentation_flag')) + '{:<24}'.format(
        'Time Lock   :  ' + total_header_data.get('time_lock_flag')))
    header_string = '\n'.join(displaydata)
    return header_string


def formPCMdisplay(header_string, total_segment_data, secondstime, formattedseconds, file):
    # type: (object, object, object, object, object) -> object
    displaydata = []
    howmanysegments = len(total_segment_data)  # figure out how many segments are in the current DAR PCM packet
    print howmanysegments
    # print total_segment_data
    displaydata.append('\n')
    displaydata.append('{:<30}'.format('Total Segments in Packet  :  ') + str(howmanysegments))
    segmentcount = howmanysegments  # initialize loop variable for writing multiple segments
    blah = header_string
    while segmentcount > 0:
        index = howmanysegments - segmentcount
        displaydata.append('')
        displaydata.append(
            '{:<24}'.format('Seg Number  :  ' + str(total_segment_data[index]['segment_count'])) + '{:<24}'.format(
                'Seg Length :  ' + str(total_segment_data[index]['seglength'])) + '{:<24}'.format(
                'Data Length :  ' + str(total_segment_data[index]['seglength'] - 12)))
        displaydata.append(
            '{:<24}'.format('1588 lock   :  ' + str(total_segment_data[index]['FPGA_sync_error'])) + '{:<24}'.format(
                'Len error  :  ' + str(total_segment_data[index]['block_len_error'])) + '{:<24}'.format(
                'CAL Valid   :  ' + str(total_segment_data[index]['CAL_valid_flag'])))
        displaydata.append(
            '{:<24}'.format('CAL 1       :  ' + str(total_segment_data[index]['CAL1_flag'])) + '{:<24}'.format(
                'CAL 2      :  ' + str(total_segment_data[index]['CAL2_flag'])) + '{:<24}'.format(
                'CAL3        :  ' + str(total_segment_data[index]['CAL3_flag'])))
        displaydata.append('{:<24}'.format(
            'Fragment    :  ' + str(total_segment_data[index]['fragmentation_flags'])) + '{:<24}'.format(
            'Simulatior :  ' + str(total_segment_data[index]['simulation_flag'])) + '{:<24}'.format(
            'SFID        :  ' + str(total_segment_data[index]['SFID'])))
        displaydata.append('')
        displaydata.append('{:<40}'.format(('Timestamp        :  ') + str(secondstime) + '.' + str(
            total_segment_data[index]['nanosecondstime']) + ' seconds'))
        displaydata.append('{:<40}'.format(('Date Timestamp   :  ') + str(formattedseconds) + '.' + str(
            total_segment_data[index]['nanosecondstime']) + ' seconds'))
        displaydata.append('')
        seg_offset = 0
        yo = []
        seg = total_segment_data[index]['rawPCMdata']
        for i in range(0, len(total_segment_data[index]['rawPCMdata']), 4):
            if i % 32 == 0:
                yo.append('\n' + str(hex(seg_offset)[2:]).zfill(8) + ' ')
                seg_offset = seg_offset + 0x10
            yo.append(seg[i:i + 4])
            # print yo
        blah = blah + '\n'.join(displaydata) + ' '.join(
            yo) + '\n'  # insert new lines in between all of the lines and make one large packet string to draw later
        yo = []
        displaydata = []
        # displaydata.append('{:<10}'.format(hex(seg_offset)[2:].zfill(8)) + total_segment_data[index]['rawPCMdata'][i-1)
        segmentcount = segmentcount - 1
        # draw_screen(T, S, b, blah, file, packetnum)
    return blah


def unknown(file, header_string, total_header_data):
    message = header_string + '\n\n' + str(hex(total_header_data.get(
        'DARtype'))) + ' packet type is not supported yet. Please contact TTC to inquire about it being added'
    file.seek(file.tell() + total_header_data.get('datalength'))  # skip over unknown data, seek to the next packet
    return message


def what_packet_is_it(DARtype):
    if DARtype == 0x9:  # MNPCM traffic
        packet_type = packettype(3)
    elif DARtype == 0xf1:  # Setup XML Packet
        packet_type = packettype(1)
    elif DARtype == 0xa1:  # PCM traffic from nDAU or MnACQ
        packet_type = packettype(2)
    elif DARtype == 0x38:  # A429 traffic from mn429
        packet_type = packettype(4)
    elif DARtype == 0xD0:  # 1553 traffic from MnHSD
        packet_type = packettype(17)
    else:  # Unknown traffic
        packet_type = packettype(23)
    return packet_type


def formA429display(header_string, secondstime, formattedseconds, total_segment_data, file):
    displaydata = []
    howmanysegments = len(total_segment_data)  # figure out how many segments are in the current DAR PCM packet
    print howmanysegments
    # print total_segment_data
    displaydata.append('\n')
    displaydata.append('{:<30}'.format('Total Segments in Packet  :  ') + str(howmanysegments))
    segmentcount = howmanysegments  # initialize loop variable for writing multiple segments
    blah = header_string
    while segmentcount > 0:
        index = howmanysegments - segmentcount
        displaydata.append('')
        displaydata.append(
            '{:<24}'.format('Seg Number  :  ' + str(total_segment_data[index]['segment_count'])) + '{:<24}'.format(
                'Seg Length :  ' + str(total_segment_data[index]['seglength'])) + '{:<24}'.format(
                'Data Length :  ' + str(total_segment_data[index]['seglength'] - 12)))
        displaydata.append('{:<24}'.format(
            'Overflow   :  ' + str(total_segment_data[index]['Overflow_flag'])) + '{:<24}'.format(
            'Simulatior :  ' + str(total_segment_data[index]['simulation_flag'])))
        displaydata.append('')
        displaydata.append('{:<40}'.format(('Timestamp        :  ') + str(secondstime) + '.' + str(
            total_segment_data[index]['nanosecondstime']) + ' seconds'))
        displaydata.append('{:<40}'.format(('Date Timestamp   :  ') + str(formattedseconds) + '.' + str(
            total_segment_data[index]['nanosecondstime']) + ' seconds'))
        displaydata.append('')
        displaydata.append(
            '{:<24}'.format('Label       :  ' + str(total_segment_data[index]['Label'])) + '{:<24}'.format(
                'SDI        :  ' + str(total_segment_data[index]['SDI'])) + '{:<24}'.format(
                'Data        :  ' + str(total_segment_data[index]['Data'])))
        displaydata.append(
            '{:<24}'.format('SSM         :  ' + str(total_segment_data[index]['SSM'])) + '{:<24}'.format(
                'Parity     :  ' + str(total_segment_data[index]['Parity'])[0]))
        displaydata.append('')
        seg_offset = 0
        yo = []
        seg = total_segment_data[index]['rawPCMdata']
        for i in range(0, len(total_segment_data[index]['rawPCMdata']), 4):
            if i % 32 == 0:
                yo.append('\n' + str(hex(seg_offset)[2:]).zfill(8) + ' ')
                seg_offset = seg_offset + 0x10
            yo.append(seg[i:i + 4])
            # print yo
        blah = blah + '\n'.join(displaydata) + ' '.join(
            yo) + '\n'  # insert new lines in between all of the lines and make one large packet string to draw later
        yo = []
        displaydata = []
        # displaydata.append('{:<10}'.format(hex(seg_offset)[2:].zfill(8)) + total_segment_data[index]['rawPCMdata'][i-1)
        segmentcount = segmentcount - 1
    return blah


def decode_429_packet(file, datalength):
    segment_count = 0
    total_list_segment_data = []
    while datalength != 0:
        segheader = file.read(8)
        nanosecondstime = struct.unpack('!i', segheader[0:4])[0]
        seglength = struct.unpack('!H', segheader[4:6])[0]
        errorcode = struct.unpack('!B', segheader[6:7])[0]
        flags = struct.unpack('!B', segheader[7:8])[0]
        print nanosecondstime
        print seglength
        print errorcode
        print flags
        overflow_flag = flags & 0x02
        simulation_flag = flags & 0x04
        if simulation_flag == 0:
            simulation_flag = 'No'
        else:
            simulation_flag = 'Yes'
        if overflow_flag == 0:
            overflow_flag = 'No'
        else:
            overflow_flag = 'Yes'
        datalength = datalength - seglength
        raw_A429_data = file.read(seglength - 8)
        A429 = struct.unpack('!i', raw_A429_data[0:4])[0]
        Label = A429 & 0x000000ff
        Label = oct(Label)
        SDI = A429 & 0x00000300 >> 8
        SDI = oct(SDI)
        Data = A429 & 0x1ffffc00 >> 10
        Data = oct(Data)
        SSM = A429 & 0x60000000 >> 29
        Parity = A429 & 0x80000000 >> 31
        if seglength % 4 != 0:  # To detect and get rid of pad
            padbytes = abs((seglength % 4) - 4)
            pad = file.read(padbytes)
            datalength = datalength - padbytes  # properly adjust data length
        rawPCMdata = ''.join(x.encode('hex') for x in raw_A429_data)
        # print rawPCMdata
        # test =
        # draw_screen(rawPCMdata)
        print datalength
        segment_data = {'segment_count': segment_count, 'nanosecondstime': nanosecondstime, 'seglength': seglength,
                        'Overflow_flag': overflow_flag, 'simulation_flag': simulation_flag, 'A429': A429,
                        'Label': Label, 'SDI': SDI, 'Data': Data, 'SSM': SSM, 'Parity': Parity,
                        'rawPCMdata': rawPCMdata}
        total_list_segment_data.append(segment_data)
        print total_list_segment_data
        segment_count = segment_count + 1
    return total_list_segment_data


def decode_1553_packet(file, datalength):
    segment_count = 0
    total_list_segment_data = []
    while datalength != 0:
        segheader = file.read(12)
        nanosecondstime = struct.unpack('!i', segheader[0:4])[0]
        seglength = struct.unpack('!H', segheader[4:6])[0]
        errorcode = struct.unpack('!B', segheader[6:7])[0]
        flags = struct.unpack('!B', segheader[7:8])[0]
        blockstatus = struct.unpack('!H', segheader[8:10])[0]
        gaptime2 = struct.unpack('!B', segheader[10:11])[0]
        gaptime1 = struct.unpack('!B', segheader[11:12])[0]
        print nanosecondstime
        print seglength
        print errorcode
        print flags
        general_error = errorcode & 0x08 >> 3  # make error code bits
        packet_underflow = errorcode & 0x04 >> 2
        FIFO_underflow = errorcode & 0x02 >> 1
        FIFO_overflow = errorcode & 0x01
        if general_error == 0:  # set error code bits to yes or no text
            general_error = 'No'
        else:
            general_error = 'Yes'
        if packet_underflow == 0:
            packet_underflow = 'No'
        else:
            packet_underflow = 'Yes'
        if FIFO_underflow == 0:
            FIFO_underflow = 'No'
        else:
            FIFO_underflow = 'Yes'
        if FIFO_overflow == 0:
            FIFO_overflow = 'No'
        else:
            FIFO_overflow = 'Yes'
        fragmentation_flags = flags & 0x06 >> 1  # decode flag bits
        simulation_flag = flags & 0x01
        if fragmentation_flags == 0:  # set flags to appropriate text decoding
            fragmentation_flags = 'Complt'
        elif fragmentation_flags == 1:
            fragmentation_flags = 'First'
        elif fragmentation_flags == 2:
            fragmentation_flags = 'Middle'
        else:
            fragmentation_flags = 'Last'
        if simulation_flag == 0:
            simulation_flag = 'No'
        else:
            simulation_flag = 'Yes'
        print fragmentation_flags, simulation_flag
        message_class = blockstatus & 0xC000 >> 14  # decode block status word
        bus_id = blockstatus & 0x2000 >> 13
        message_error = blockstatus & 0x1000 >> 12
        rt_to_rt = blockstatus & 0x0800 >> 11
        format_error = blockstatus & 0x0400 >> 10
        timeout = blockstatus & 0x0200 >> 9
        word_count_error = blockstatus & 0x0020 >> 5
        sync_type_error = blockstatus & 0x0010 >> 4
        invalid_word_error = blockstatus & 0x0008 >> 3
        simulator_enable = blockstatus & 0x0001
        if message_class == 0:  # set block status to appropriate text decoding
            message_class = 'Norml'
        elif message_class == 1:
            message_class = 'Unclass'
        elif message_class == 2:
            message_class = 'Class'
        else:
            message_class = 'Reserved'
        if bus_id == 0:
            bus_id = 'A'
        else:
            bus_id = 'B'
        if message_error == 0:
            message_error = 'No'
        else:
            message_error = 'Yes'
        if rt_to_rt == 0:
            rt_to_rt = 'No'
        else:
            rt_to_rt = 'Yes'
        if format_error == 0:
            format_error = 'No'
        else:
            format_error = 'Yes'
        if timeout == 0:
            timeout = 'No'
        else:
            timeout = 'Yes'
        if word_count_error == 0:
            word_count_error = 'No'
        else:
            word_count_error = 'Yes'
        if sync_type_error == 0:
            sync_type_error = 'No'
        else:
            sync_type_error = 'Yes'
        if invalid_word_error == 0:
            invalid_word_error = 'No'
        else:
            invalid_word_error = 'Yes'
        if simulator_enable == 0:
            simulator_enable = 'No'
        else:
            simulator_enable = 'Yes'
        gaptime1 *= 0.1  # put gaptime words in units of microseconds
        gaptime2 *= 0.1
        datalength = datalength - seglength
        raw_1553_data = file.read(seglength - 12)
        if seglength % 4 != 0:  # To detect and get rid of pad
            padbytes = abs((seglength % 4) - 4)
            pad = file.read(padbytes)
            datalength = datalength - padbytes  # properly adjust data length
        data_1553 = ''.join(x.encode('hex') for x in raw_1553_data)
        # print rawPCMdata
        # test =
        # draw_screen(rawPCMdata)
        # print rawPCMdata
        # test =
        # draw_screen(rawPCMdata)
        print datalength
        segment_data = {'segment_count': segment_count, 'nanosecondstime': nanosecondstime, 'seglength': seglength,
                        'Gen error': general_error, 'Pkt Udrflw': packet_underflow,
                        'FIFO Ovrflw': FIFO_overflow, 'FIFO Udrflw': FIFO_underflow, 'simulation_flag': simulation_flag,
                        'Msg Class': message_class, 'Bus ID': bus_id, 'Msg Error': message_error,
                        'RT_to_RT': rt_to_rt, 'Fmt error': format_error, 'Rsp timeout': timeout,
                        'Word Cnt Error': word_count_error, 'Sync error': sync_type_error,
                        'Invld word error': invalid_word_error, 'Sim enabled': simulator_enable, 'Gaptime 1': gaptime1,
                        'Gaptime 2': gaptime2, 'Raw_1553': data_1553}
        total_list_segment_data.append(segment_data)
        print total_list_segment_data
        segment_count += 1
    return total_list_segment_data


def form1553display(header_string, secondstime, formattedseconds, total_segment_data, file):
    displaydata = []
    howmanysegments = len(total_segment_data)  # figure out how many segments are in the current DAR PCM packet
    print howmanysegments
    # print total_segment_data
    displaydata.append('\n')
    displaydata.append('{:<30}'.format('Total Segments in Packet  :  ') + str(howmanysegments))
    segmentcount = howmanysegments  # initialize loop variable for writing multiple segments
    blah = header_string
    while segmentcount > 0:
        index = howmanysegments - segmentcount
        displaydata.append('')
        displaydata.append(
            '{:<24}'.format('Seg Number  :  ' + str(total_segment_data[index]['segment_count'])) + '{:<24}'.format(
                'Seg Length :  ' + str(total_segment_data[index]['seglength'])) + '{:<24}'.format(
                'Data Length :  ' + str(total_segment_data[index]['seglength'] - 12)))
        displaydata.append('{:<24}'.format(
            'FIFO Ovrflw :  ' + str(total_segment_data[index]['FIFO Ovrflw'])) + '{:<24}'.format(
            'FIFO Urflw :  ' + str(total_segment_data[index]['FIFO Udrflw'])) + '{:<24}'.format(
            'Pkt Udrflw  :  ' + str(total_segment_data[index]['Pkt Udrflw'])))
        displaydata.append('{:<24}'.format('Simulatior  :  ' + str(total_segment_data[index]['simulation_flag'])))
        displaydata.append('')
        displaydata.append('{:<24}'.format('Bus ID      :  ' + str(total_segment_data[index]['Bus ID'])) + '{:<24}'.format(
                'RT to RT   :  ' + str(total_segment_data[index]['RT_to_RT'])) + '{:<24}'.format(
                'Msg Class   :  ' + str(total_segment_data[index]['Msg Class'])))
        displaydata.append(
            '{:<24}'.format('Gen Error   :  ' + str(total_segment_data[index]['Gen error'])) + '{:<24}'.format(
                'Msg Error  :  ' + str(total_segment_data[index]['Msg Error'])) + '{:<24}'.format(
                'Fmt Error   :  ' + str(total_segment_data[index]['Fmt error'])))
        displaydata.append(
            '{:<24}'.format('Wrd Cnt Err :  ' + str(total_segment_data[index]['Word Cnt Error'])) + '{:<24}'.format(
                'Sync error :  ' + str(total_segment_data[index]['Sync error'])) + '{:<24}'.format(
                'Ivd wrd err :  ' + str(total_segment_data[index]['Invld word error'])))
        displaydata.append(
            '{:<24}'.format('Rsp timeout :  ' + str(total_segment_data[index]['Rsp timeout'])) + '{:<24}'.format(
                'Gaptime 1  :  ' + str(total_segment_data[index]['Gaptime 1'])) + '{:<24}'.format(
                'Gaptime 2   :  ' + str(total_segment_data[index]['Gaptime 2'])))
        displaydata.append('')
        displaydata.append('{:<40}'.format(('Timestamp        :  ') + str(secondstime) + '.' + str(
            total_segment_data[index]['nanosecondstime']) + ' seconds'))
        displaydata.append('{:<40}'.format(('Date Timestamp   :  ') + str(formattedseconds) + '.' + str(
            total_segment_data[index]['nanosecondstime']) + ' seconds'))
        displaydata.append('')
        seg_offset = 0
        yo = []
        seg = total_segment_data[index]['Raw_1553']
        for i in range(0, len(total_segment_data[index]['Raw_1553']), 4):
            if i % 32 == 0:
                yo.append('\n' + str(hex(seg_offset)[2:]).zfill(8) + ' ')
                seg_offset = seg_offset + 0x10
            yo.append(seg[i:i + 4])
            # print yo
        blah = blah + '\n'.join(displaydata) + ' '.join(
            yo) + '\n'  # insert new lines in between all of the lines and make one large packet string to draw later
        yo = []
        displaydata = []
        # displaydata.append('{:<10}'.format(hex(seg_offset)[2:].zfill(8)) + total_segment_data[index]['rawPCMdata'][i-1)
        segmentcount = segmentcount - 1
    return blah
    '''displaydata.append(
        '{:<24}'.format('Label       :  ' + str(total_segment_data[index]['Label'])) + '{:<24}'.format(
            'SDI        :  ' + str(total_segment_data[index]['SDI'])) + '{:<24}'.format(
            'Data        :  ' + str(total_segment_data[index]['Data'])))
    displaydata.append(
        '{:<24}'.format('SSM         :  ' + str(total_segment_data[index]['SSM'])) + '{:<24}'.format(
            'Parity     :  ' + str(total_segment_data[index]['Parity'])[0]))
    displaydata.append('')
    seg_offset = 0
    yo = []
    seg = total_segment_data[index]['rawPCMdata']
    for i in range(0, len(total_segment_data[index]['rawPCMdata']), 4):
        if i % 32 == 0:
            yo.append('\n' + str(hex(seg_offset)[2:]).zfill(8) + ' ')
            seg_offset = seg_offset + 0x10
        yo.append(seg[i:i + 4])
        # print yo
    blah = blah + '\n'.join(displaydata) + ' '.join(
        yo) + '\n'  # insert new lines in between all of the lines and make one large packet string to draw later
    yo = []
    displaydata = []
    # displaydata.append('{:<10}'.format(hex(seg_offset)[2:].zfill(8)) + total_segment_data[index]['rawPCMdata'][i-1)
    segmentcount = segmentcount - 1
return blah
return 'This is still being coded'''


def decode_XML_packet(file, datalength):
    archive = open('DARXMLTemp.tar.gz', 'wb')
    trash = file.read(8)
    datalength = datalength - 8
    print datalength
    totaldata = datalength
    x = 0
    while datalength >= 32740:
        # file.seek(file.tell()+1)
        hey = file.tell()
        if x == 0:
            string = file.read(datalength)
            totaldata = string
        else:
            header = file.read(20)  # read the 20 byte header
            DARsync = struct.unpack('!B', header[0:1])[0]  # read 20 byte DAR header into own variables
            DARtype = struct.unpack('!B', header[1:2])[0]
            if DARtype != 0xf1: #handles case when exactly 32768 bytes of XML packet
                file.seek(file.tell()-20)
                datalength = 0
                break
            packetlength = struct.unpack('!H', header[2:4])[0]
            packetlength = packetlength * 4
            datalength = packetlength - 20
            trash = file.read(8)
            datalength = datalength - 8
            string = file.read(datalength)
            totaldata = totaldata + string
        x += 1
        print 'XML position: ' + str(file.tell())
    # tarball = file.read(totaldata)
    # testtarball = ''.join(x.encode('hex') for x in tarball)
    archive.write(totaldata)
    tar = tarfile.open('DARXMLTemp.tar.gz')
    hit = tar.getnames()
    tar.extract(hit[0])
    f = open(hit[0], 'r')
    buf = f.read()
    doc = etree.fromstring(buf)
    DSID = doc.xpath("//@DSID")  # find all DSID attributes and put in a list
    elementDSID = doc.xpath('//DSID/text()')  # find all DSID elements and put in a list
    camID = doc.xpath('//@CameraID')  # find all CameraID elements and put in a list
    allDSIDs = DSID + elementDSID + camID
    allDSIDs = list(set(allDSIDs))
    allDSIDs.sort(key=int)
    print allDSIDs
    print 'XML position: ' + str(file.tell())
    return buf, allDSIDs


def decode_PCM_packet(file, datalength):
    segment_count = 0
    total_list_segment_data = []
    while datalength != 0:
        segheader = file.read(12)
        nanosecondstime = struct.unpack('!i', segheader[0:4])[0]
        seglength = struct.unpack('!H', segheader[4:6])[0]
        errorcode = struct.unpack('!B', segheader[6:7])[0]
        flags = struct.unpack('!B', segheader[7:8])[0]
        SFID = struct.unpack('!B', segheader[8:9])[0]
        CALflags = struct.unpack('!B', segheader[9:10])[0]
        reserved = struct.unpack('!H', segheader[10:12])[0]
        print nanosecondstime
        print seglength
        print errorcode
        print flags
        CAL_valid_flag = flags & 0x80
        fragmentation_flags = flags & 0x06 >> 1
        simulation_flag = flags & 0x01
        if CAL_valid_flag == 0:  # set flags to no and yes string instead of 0 and 1
            CAL_valid_flag = 'No'
        else:
            CAL_valid_flag = 'Yes'
        if fragmentation_flags == 0:
            fragmentation_flags = 'Complt'
        elif fragmentation_flags == 1:
            fragmentation_flags = 'First'
        elif fragmentation_flags == 2:
            fragmentation_flags = 'Middle'
        else:
            fragmentation_flags = 'Last'
        if simulation_flag == 0:
            simulation_flag = 'No'
        else:
            simulation_flag = 'Yes'
        print fragmentation_flags, simulation_flag, CAL_valid_flag
        FPGA_sync_error = errorcode & 0x04
        block_len_error = errorcode & 0x02
        if FPGA_sync_error == 0:  # set flags to no and yes string instead of 0 and 1
            FPGA_sync_error = 'Yes'
        else:
            FPGA_sync_error = 'No'
        if block_len_error == 0:
            block_len_error = 'None'
        else:
            block_len_error = 'Error'
        print FPGA_sync_error, block_len_error
        CAL3_flag = CALflags & 0x04
        CAL2_flag = CALflags & 0x02
        CAL1_flag = CALflags & 0x01
        if CAL3_flag == 0:  # set flags to no and yes string instead of 0 and 1
            CAL3_flag = 'Off'
        else:
            CAL3_flag = 'On'
        if CAL2_flag == 0:
            CAL2_flag = 'Off'
        else:
            CAL2_flag = 'On'
        if CAL1_flag == 0:
            CAL1_flag = 'Off'
        else:
            CAL1_flag = 'On'
        datalength = datalength - seglength
        PCM_data = file.read(seglength - 12)
        if seglength % 4 != 0:  # To detect and get rid of pad
            padbytes = abs((seglength % 4) - 4)
            pad = file.read(padbytes)
            datalength = datalength - padbytes  # properly adjust data length
        rawPCMdata = ''.join(x.encode('hex') for x in PCM_data)
        print datalength
        segment_data = {'segment_count': segment_count, 'nanosecondstime': nanosecondstime, 'seglength': seglength,
                        'FPGA_sync_error': FPGA_sync_error, 'block_len_error': block_len_error,
                        'CAL_valid_flag': CAL_valid_flag, 'fragmentation_flags': fragmentation_flags,
                        'simulation_flag': simulation_flag, 'SFID': SFID, 'CAL3_flag': CAL3_flag,
                        'CAL2_flag': CAL2_flag, 'CAL1_flag': CAL1_flag, 'reserved': reserved, 'rawPCMdata': rawPCMdata}
        total_list_segment_data.append(segment_data)
        print total_list_segment_data
        segment_count = segment_count + 1
    return total_list_segment_data


def main():
    root = Tk()
    ex = window(root)
    root.geometry('1024x600')
    root.mainloop()


if __name__ == '__main__':
    main()
