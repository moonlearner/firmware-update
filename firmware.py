import pexpect
import requests
import sys
import logging
import badtime
import multiprocessing
import concurrent.futures
import quantaskylake
import json
import minios

class firmware(object):

    def __init__(self, host, username, password):
        self.host = host

        # Some applications do not work via IPv6 Link Local. Adding ipv6linklocal instance
        self.hostforwardinstance = None

        self.username = username
        self.password = password
        self.redfishapi = 'https://[' + host.replace('%','%25') + ']/redfish/v1/'
        self.redfishheader = {
                                'Content-Type': 'application/json',
                                'User-Agent': 'curl/7.54.0',
                                'Host': '[' + host.split('%')[0] + ']'
                            }
        self.amiheader = {}
        self.amiloggedin = False
        self.preserveconfig = True
        self.cookie = None
        self.token = None
        self.BMCVersion = None
        self.BIOSVersion = None
        self.BIOSJSONCache = None
        self.ManagersJSONCache = None
        self.SystemsJSONCache = None
        self.IPMIPre = 'ipmitool -I lanplus -H ' + host + ' -U ' + username + ' -P ' + password + ' '
        self.ipv4Address = None
        self.ipv4Subnet = None
        self.ipv4Gateway = None
        self.ipv4Src = None
        self.mgmtMAC = None
        self.lastButtonTime = None
        self.SOLSession = None
        self.VMCLISession = None
        # Fill UP JSON Cache
        #self.getJSONs()

        self.firmwaredictionary = {
            ("D52B", "DS120", "DS220"): {
                "2017-09-08": {
                    "BMC": {"Version": "3.16.06", "File": "s5bxv3.16.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A08.H2", "File": "3A08.BIN"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed"}
                },
                "2018-01-17": {
                    "BMC": {"Version": "3.74.06", "File": "s5bxv3.74.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A10.H3", "File": "3A10.H3.BIN"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed"}
                }
            }
        }

        if 'linux' in sys.platform:
            self.path = '../../Firmware/COMPUTE/'
        else:
            self.path = '..\\..\\Firmware\\COMPUTE\\'

    def printfirmwareselection(self, name):
            print('Firmware Selection for ' + str(name) + ':')
            for device, data in self.firmwaredictionary.items():
                print(device)
                print(data)
                if name in device:
                    print(json.dumps(data, indent=4))
            return None

    def spawn(self, command, **kwargs):
        if 'linux' in sys.platform:
            #session = PopenSpawn(command, **kwargs)
            #session = PopenSpawn(command)
            session = pexpect.spawn(command)
        else:
            #session = pexpect.spawn(command, **kwargs)
            #session = pexpect.spawn(command)
            print("Not support OS")
        return session

        # Start AMI Section
        # DO NOT USE THIS FOR OFFICIAL PURPOSES. ONLY CREATED FOR BMC 4.22.06 PURPOSES SINCE WE CAN'T LOG INTO REDFISH AT INITIAL BMC BOOTUP.
        # FORCE CHANGE PASSWORD TO SAME PASSWORD

    def poweroff(self):
        # session = PopenSpawn(self.IPMIPre + ' power off')
        session = self.spawn(self.IPMIPre + ' power off')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.replace('\n', '')
        print(self.host + ' ' + output)

    def poweron(self):
        # session = PopenSpawn(self.IPMIPre + ' power on')
        session = self.spawn(self.IPMIPre + ' power on')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.replace('\n', '')
        print(self.host + ' ' + output)

    def powersoft(self):
        # If node is on, press power button softly.
        if self.getPowerStatus():
            # session = PopenSpawn(self.IPMIPre + ' power soft')
            session = self.spawn(self.IPMIPre + ' power soft')
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' ' + output)

    def forcePasswordChange(self):
        # Get QSESSIONID and X-CSRFTOKEN to log into AMI API
        header = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.54.0',
                  'Host': '[' + self.host.split('%')[0] + ']'}
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.post(url=url_prep + 'api/session', data="username=admin&password=cmb9.admin", headers=header,
                                verify=False)
        if session.ok:
            try:
                j = session.json()
            except:
                print(self.host + " Failed to Force Change Password")
                return False
            # print(j)
            CSRFToken = j["CSRFToken"]
            QSESSIONID = session.cookies["QSESSIONID"]
        else:
            print(self.host + " Failed to Force Change Password")
            return False

        # Update Header with QSESSIONID, X-CSRFTOKEN Details and new Content Type
        header.update({'Cookie': 'QSESSIONID=' + QSESSIONID})
        header.update({"X-CSRFTOKEN": CSRFToken})
        header.update({'Content-Type': 'application/json'})

        session = requests.post(url=url_prep + 'api/force_change_password',
                                data="{\"this_userid\":\"2\",\"password\":\"cmb9.admin\",\"confirm_password\":\"cmb9.admin\",\"password_size\":\"0\"}",
                                headers=header, verify=False)
        if session.ok:
            print(self.host + " Successfully Force Change Password")
        else:
            print(self.host + " Failed to Force Change Password")

        # Don't forget to log our of session
        session = requests.delete(url=url_prep + 'api/session', headers=header, verify=False)
        if session.ok:
            return True
        else:
            print(self.host + " Failed to Force Change Password")
            return False

    def createAPISession(self):
        # Get QSESSIONID and X-CSRFTOKEN to log into AMI API
        self.amiheader = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.54.0',
                          'Host': '[' + self.host.split('%')[0] + ']'}
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.post(url=url_prep + 'api/session', data="username=admin&password=cmb9.admin",
                                headers=self.amiheader, verify=False)
        if session.ok:
            try:
                j = session.json()
            except:
                print(self.host + " Failed to log into AMI Session")
                return False
            # print(j)
            CSRFToken = j["CSRFToken"]
            QSESSIONID = session.cookies["QSESSIONID"]
        else:
            print(self.host + " Failed to log into AMI Session")
            return False

        # Update Header with QSESSIONID, X-CSRFTOKEN Details and new Content Type
        self.amiheader.update({'Cookie': 'QSESSIONID=' + QSESSIONID})
        self.amiheader.update({"X-CSRFTOKEN": CSRFToken})
        self.amiheader.update({'Content-Type': 'application/json'})

        self.amiloggedin = True

    def destroyAPISession(self):
        # Don't forget to log our of session
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.delete(url=url_prep + 'api/session', headers=self.amiheader, verify=False)
        if session.ok:
            self.amiloggedin = False
            return True
        else:
            print(self.host + " Failed to lot out of AMI session")
            return False

    def getVirtualMediaStatus(self):
        if self.amiloggedin:
            pass
        else:
            return {}
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.get(url=url_prep + 'api/settings/media/instance', headers=self.amiheader, verify=False)

        if session.ok:
            try:
                j = session.json()
            except:
                return {}

        return j

 # Each Redfish Update Requires just one PUT Call. Can't use multiple PUT Calls
    def setMiniOSDefaults(self):
        try:
            session = requests.put(self.redfishapi + 'Systems/Self/Bios/SD', auth=(self.username, self.password),\
                                   verify=False, headers=self.redfishheader,\
                                   # data='{"Attributes":{"FBO001":"LEGACY","FBO101":"CD/DVD","FBO102":"USB","FBO103":"Hard Disk","FBO104":"Network"}}')\
        
                                   data='{"Attributes":{"FBO001":"UEFI","FBO201":"CD/DVD","FBO202":"USB","FBO203":"Hard Disk","FBO204":"Network","CRCS005":"Enable","IIOS1FE":"Enable", "IPMI100":"Disabled"}}')
            if session.status_code == 204:
                print(self.host + ' ' + 'Successfully set MiniOS BIOS Settings')
            else:
                print(self.host + ' ' + 'Failed to set MiniOS BIOS Settings')

        except:
            pass
        #if session.status_code == 204:
        #    print(self.host + ' ' + 'Successfully set MiniOS BIOS Settings')
        #else:
        #    print(self.host + ' ' + 'Failed to set MiniOS BIOS Settings')


    def miniospcidiscoverwrapper(minios_instance):
        minios_instance.discoverPCIDeiveices()
        return minios_instance

    def pciflashing(minios_instance, firmware_class, firmware_selection):
        for pciloc, device in minios_instance.PCIDevices.items():
            date = firmware_selection.get("IOCards").get(device.name, None)
            if date is None:
                print(
                    minios_instance.node.host + "" + device.name + " isn\'t compatible wit this firmware selction or firmware doesn\]'t exit.")
                continue
            filejson = firmware_class.returnfirmwarefileJSON(device.name, date)
            # This path is relative to the MiniOS
            filepath = "/cdrom/firmware/" + device.name + "/" + filejson.get("File")
            print(minios_instance.node.host + ' Flashing ' + device.name + ' on ' + pciloc + ' with ' + filepath)
            device.flash(filepath)
        return minios_instance



    # nodes = [quantaskylake.DS120('fe80::dac4:97ff:fe1c:4e26%11', 'admin', 'cmb9.admin')]
    # # Start MiniOS Logic
    # badtime.seperate()
    # print("\nStarting PCI Device Firmware Flashing\n")
    # 
    # print("Setting MiniOS BIOS Default")
    # processes = []
    # for node in nodes:
    #     processes.append(multiprocessing.Process(target=node.setMiniOSDefaults))
    # 
    # # Start threads
    # for process in processes:
    #     process.start()
    #     # Slowly power-on nodes to not overload circuit
    #     time.sleep(2)
    # 
    # # Wait for threads
    # for process in processes:
    #     process.join()
    # 
    # print("\nCreating MiniOS Instances")
    # minioses = []
    # for node in nodes:
    #     minioses.append(minios.minios(node))
    # 
    # print("\nAttempting to login into all MiniOS Instances")
    # for minios_instance in minioses:
    #     minios_instance.login()
    # 
    # time.sleep(30)
    # 
    # print("\nDiscovering All PCI Devices in all MiniOS instance")
    # temp_minioses = []
    # with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
    #     futures = [executor.submit(miniospcidiscoverwrapper, minios_instance) for minios_instance in minioses]
    #     for future in concurrent.futures.as_completed(futures):
    #         temp_minioses.append(future.result())
    # minioses = temp_minioses
    # 
    # for minios_instance in minioses:
    #     minios_instance.printPCIDeices()
    # 
    # 
    # print("\nFlashing All PCI Deivce in all MiniOS Instances")
    # temp_minioses = []
    # with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
    #     futures = [executor.submit(pciflashing, minios_instance, firmware, firmwareselection) for minios_instance in minioses]
    #     for future in concurrent.futures.as_completed(futures):
    #         try:
    #             temp_minioses.append(future.result())
    #         except:
    #             continue
    # minioses = temp_minioses
    # 
    # input("Hit enter to continue")
    # 
    # # Power off the nodes
    # for node in nodes:
    #     node.poweroff()
    # 
    # if preserveconfig is True:
    #     badtime.seperate()
    #     print("Starting BIOS Restore\n")
    #     for node in nodes:
    #         # Double check if the node has BIOS Version. If not, wait until node is powered on to get versions.
    #         count = 0
    #         print(node.host + ' Sarting BIOIS Restore ')
    #         while count < 15:
    #             data = node.getSystemsJSON()
    #             count = count + 1
    #             try:
    #                 biosversion = data['BiosVersion']
    #             except:
    #                 print(node.host + ' Missing BiosVersion. Checking again in a minute.')
    #                 time.sleep(60)
    #                 continue
    # 
    #             if len(biosversion) < 1:
    #                 print(node.host + ' BiosVersion is still blank. Checking again in a minute. ')
    #                 time.sleep(60)
    #                 continue
    #             else:
    #                 node.poweroff(0)
    #                 break
    # 
    # if count > 14:
    #     print(node.host + ' WARNING!!! THIS NODE ISN\'T RESPONSING!!! HELP!!! (Also skipping this node.)'
    # 
    # # Compare BIOS JSON Cache Attributes with Registries Attributes and create new JSON out of existing keys in new BIOS Firmware Registries
    # # Get BIOS JSON Registries
    #     data = node.getBIOSJSONRegistries()
    #     newBIOSJSON = {'Attributes': {}}
    #     for key in data.get('RegistryEntries').get('Attributes'):
    #         if key['AttributeName'] in node.BIOSJSONCache['Attributes']:
    #             # D52B BMC 3.16.06 has bad default key ISCS003. Ignore it
    #             # Q72D BMC 3.85.06 can't update GSIO keys for some reason. IDK why.
    #             # D52B/Q72D BMC 4.23.06 can not update OEMSECBOOTMODE key. Read-only keys.
    #             # If key is blank in key, do not add it.
    #     if 'ISCS003' in key['AttributeName'] or \
    #             '  ' in str(node.BIOSJSONCache['Attributes'][key['AttributeName']]) or \
    #             len(str(node.BIOSJSONCache['Attributes'][key['AttributeName']])) < 1 or \
    #             'GSIO' in key['AttributeName'] or \
    #             'OEMSECBOOTMODE' in key['AttributeName'] or \
    #             'OEMSECBOOT' in key['AttributeName']:
    #         continue
    #     else:
    #         newBIOSJSON['Attributes'].update({key['AttributeName']: node.BIOSJSONCache['Attributes'][key['AttributeName']]})
    # 
    # 
    # print(node.host + ' Restoring the following BIOS settings ' + str(newBIOSJSON))
    # node.restoreBIOSJSON(newBIOSJSON)
    # 
    # print('\n All Done. :D\n\n')
    # badtime.okay()
    # 

def main():
    preserveconfig = True

    # # Get the existing nodes
    # if preserveconfig is True:
    #     # Discover with existing details
    #     nodes = autodiscover.discover(nodesnum, [username], [password])
    # else:
    #     # Discover with default details
    #     nodes = autodiscover.discover(nodesnum)

    nodes = ['fe80::dac4:97ff:fe17:6e7c%ens160']
    r = firmware('fe80::dac4:97ff:fe17:6e7c%ens160', 'admin', 'cmb9.admin')
    r.printfirmwareselection("DS120")
    # Start MiniOS Logic
    badtime.seperate()
    print("\nStarting PCI Device Firmware Flashing\n")

    print('Setting MiniOS BIOS Default')
    processes = []
    for node in nodes:
        processes.append(multiprocessing.Process(target=r.setMiniOSDefaults()))
    # Start threads
    for process in processes:
        process.start()
        time.sleep(1)
    # Wait for threads
    for process in processes:
        process.join()

    print('Powering on the nodes to start MiniOS')
    processes = []
    for node in nodes:
        processes.append(multiprocessing.Process(target=r.poweron))
    # Start threads
    for process in processes:
        process.start()
        # Slowly power-on nodes to not overload circuit
        time.sleep(2)
    # Wait for threads
    for process in processes:
        process.join()

    print("\nCreating MiniOS Instances")
    minioses = []
    for node in nodes:
        minioses.append(minios.minios(node))

    print("\nAttempting to login into all MiniOS Instances")
    for minios_instance in minioses:
        minios_instance.login()

    time.sleep(30)

if __name__ == '__main__':
    '''
    from argparse import ArgumentParser

    logging.basicConfig(format='%(asctime)s %(name)-5s %(levelname)-10s %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    parser = ArgumentParser()
    parser.add_argument('-h_list', type=str, nargs='*', dest='hostname', help='Hostname list for BMC')
    parser.add_argument('-u_list', type=str, nargs='*', dest='username', help='Username list for BMC')
    parser.add_argument('-p_list', type=str, nargs='*', dest='password', help='Password List for BMC')
    args = parser.parse_args()


    # nodes = [quantaskylake.DS120('fe80::dac4:97ff:fe1c:4e26%11', 'admin', 'cmb9.admin')]
    try:
        if isinstance(args.username, list) and isinstance(args.password, list):
            autodiscover = QuantaSkylake(args.hostname, args.username, args.password)
            print(autodiscover.firmware())
        else:
            parser.print_help()
    except Exception as ex:
        print('Exception| ', ex)
        '''
    main()
