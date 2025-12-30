import argparse
import ipaddress
import logging
import os

import netmiko
from netmiko.ssh_autodetect import SSHDetect
from netmiko import ConnectHandler

class NetworkDevice:
    def __init__(self, host, username, password, device_type):
        self.device_params = {
            'host': str(host),
            'username': username,
            'password': password,
            'device_type': device_type,
        }
        self.connection = None

    def __repr__(self):
        return f'<{self.__class__.__name__} host={self.device_params["host"]}>'

    VENDOR_MAP = {}
    
    @classmethod
    def from_ip(cls, ip_input, device_type=None, **kwargs):
        network = ipaddress.ip_network(ip_input, strict=False)
        # Implement error handling
        hosts = list(network.hosts()) or [network.network_address]

        devices = []
        for host in hosts:
            target_class = cls
            current_type = device_type

            if not current_type or current_type == 'autodetect':
                current_type = cls.get_vendor(str(host), **kwargs)
                logging.info(f"Autodetected device type: {current_type}")

            if current_type in cls.VENDOR_MAP:
                target_class = cls.VENDOR_MAP[current_type]

            devices.append(target_class(host=str(host), device_type=current_type, **kwargs))

        return devices

    @classmethod
    def get_vendor(cls, host, **kwargs):
        guesser = SSHDetect(host, device_type='autodetect', **kwargs)
        best_match = guesser.autodetect()
        return best_match

    def connect(self):
        try:
            self.connection = ConnectHandler(**self.device_params)
            logging.info(f"Connected to {self.device_params['host']}")
        except netmiko.NetmikoAuthenticationException:
            logging.error('Authentication failed')
        except netmiko.NetMikoTimeoutException:
            logging.error('Connection timed out')
        except Exception as e:
            logging.error(f'Connection error: {e}')
    
    def send_command(self, command):
        if not self.connection:
            raise ValueError('Not connected to device. Call connect() first.')
        try:
            logging.info(f"Sending command: {command} with device_type: {self.connection.device_type}")
            
            custom_template = os.path.join('custom_templates', f'{self.connection.device_type}_{command.replace(" ", "_")}.textfsm')
            
            if os.path.exists(custom_template):
                logging.info(f"Using custom template: {custom_template}")
                output = self.connection.send_command(command, use_textfsm=True, textfsm_template=custom_template)
            else:
                output = self.connection.send_command(command, use_textfsm=True)
            
            # Check if TextFSM parsing was successful
            # If parsing fails, netmiko returns raw string instead of list
            if isinstance(output, str):
                logging.warning(f'TextFSM parsing failed for command "{command}". No template found or parsing error. Returning raw output.')
                logging.debug(f"Raw output: {output}")
            else:
                logging.info(f'TextFSM successfully parsed command: {command}')
                logging.debug(f"Structured data: {output}")
            
            logging.info(f'Executed command: {command}')
            return output
        except Exception as e:
            logging.error(f'Error sending command "{command}": {e}')
            raise

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            logging.info(f'Disconnected from {self.device_params["host"]}')
            self.connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

class HuaweiVrpSwitch(NetworkDevice):
    def __init__(self, host, username, password, device_type='huawei_vrp'):
        # Ensure we use huawei_vrp for ntc-templates compatibility
        if device_type == 'huawei':
            logging.info("Changing device_type from 'huawei' to 'huawei_vrp' for ntc-templates compatibility")
            device_type = 'huawei_vrp'
        super().__init__(host, username, password, device_type)

        self.vendor = 'Huawei'
        self.platform = 'VRP'

    def get_serial_number(self, software_version):
        """
        Docstring for get_serial_number
        
        :param software_version: Either V200 or V600
        """
        if software_version == "V200":
            output = self.send_command("display device manufacturer-info")
        elif software_version == "V600":
            output = self.send_command("display device esn")
        else:
            raise ValueError(f'Unsupported software Version: {software_version}')
        return output

    def get_software_release():
        print('display startup')

    def get_hostanme():
        print('display sysname')

    def get_vlans():
        print('display vlan')
    
    def get_interfaces():
        print('display port vlan')
    
    def get_interfaces_brief():
        print('display interface brief')
    
    def get_config():
        print('display current-configuration')

NetworkDevice.VENDOR_MAP['huawei'] = HuaweiVrpSwitch
NetworkDevice.VENDOR_MAP['huawei_vrp'] = HuaweiVrpSwitch

def main():
    parser = argparse.ArgumentParser(description='Network Switches Discovery Tool')
    parser.add_argument('-i', '--ip', type=str, help='IP address or range of the network switch', required=True)
    parser.add_argument('-u', '--user', type=str, help='Name of the SSH User which will be used to connect to the switch', required=True)
    parser.add_argument('-p', '--password', type=str, help='Password of SSH USer', required=True)

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    devices = NetworkDevice.from_ip(ip_input=args.ip, device_type='autodetect', username=args.user, password=args.password)

    print(devices)

    for device in devices:
        with device as dev:
            try:
                if isinstance(dev, HuaweiVrpSwitch):
                    output = dev.get_serial_number('V600')
                    import json
                    print(json.dumps(output, indent=4))
            except Exception as e:
                logging.error(f'Failed to get data from {dev.device_params["host"]}: {e}')

     
    print(devices)

if __name__ == "__main__":
    main()