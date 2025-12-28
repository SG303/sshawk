import argparse
import ipaddress
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
                current_type = cls.detect_vendor(str(host), **kwargs)

            if current_type in cls.VENDOR_MAP:
                target_class = cls.VENDOR_MAP[current_type]

            devices.append(target_class(host=str(host), device_type=current_type, **kwargs))

        return devices


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

    def get_serial_number(self, software_version):
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

NetworkDevice.VENDOR_MAP['huawei'] = HuaweiVrpSwitch

def main():
    parser = argparse.ArgumentParser(description='Network Switches Discovery Tool')
    parser.add_argument('-i', '--ip', type=str, help='IP address or range of the network switch', required=True)
    parser.add_argument('-u', '--user', type=str, help='Name of the SSH User which will be used to connect to the switch', required=True)
    parser.add_argument('-p', '--password', type=str, help='Password of SSH USer', required=True)

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)



    devices = NetworkDevice.from_ip(ip_input=args.ip, device_type='huawei', username=args.user, password=args.password)
        
    for device in devices:
        with device as dev:
            try:
                if isinstance(dev, HuaweiVrpSwitch):
                    output = dev.get_serial_number('V600')
            except Exception as e:
                logging.error(f'Failed to get data from {dev.device_params["host"]}: {e}')                    

     
    print(output)
    print(devices)

    if dev.vendor == 'Huawei':
        print(dev.vendor)

if __name__ == "__main__":
    main()


