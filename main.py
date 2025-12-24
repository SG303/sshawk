import argparse
import ipaddress
import sys
import logging

import netmiko
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

    @classmethod
    def autodetect(cls):
        print("test")

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
            output = self.connection.send_command(command, use_textfsm=True)
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
    def __init__(self, host, username, password, device_type='huawei'):
        super().__init__(host, username, password, device_type)

        self.vendor = 'Huawei'
        self.platform = 'VRP'

    def  get_serial_number(self, software_version):
        """
        Docstring for get_serial_number
        
        :param software_version: Either V200 or V600
        """
        if software_version == "V200":
            output = self.send_command("display device manufacturer-info")
        elif software_version == "V600":
            output = self.send_command("display device")
        else:
            raise ValueError(f'Unsupported software Version: {software_version}')
        return output

            

def main():
    parser = argparse.ArgumentParser(description='Network Switches Dicovery Tool')
    parser.add_argument('-i', '--ip', type=str, help='IP address or range of th network switch', required=True)
    parser.add_argument('-u', '--user', type=str, help='Name of the SSH User which will be used to connect to the switch', required=True)
    parser.add_argument('-p', '--password', type=str, help='Password of SSH USer', required=True)

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)


    try:   
        network = ipaddress.IPv4Network(args.ip)
    except ValueError as e:
        logging.error(f'Error {e}')
        raise

    for ip in network.hosts():
        device = HuaweiVrpSwitch(ip, args.user, args.password)
        with device as dev:
            try:
                output = dev.get_serial_number('V600')
                logging.info(f'Output from {ip}: {output}')
            except Exception as e:
                logging.error(f"Error with {ip}: {e}")

if __name__ == "__main__":
    main()


