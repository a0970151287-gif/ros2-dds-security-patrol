from setuptools import setup
import os
from glob import glob

package_name = 'dds_security_monitor'

setup(
    name=package_name,
    version='1.0.0',
    packages=[package_name],
    data_files=[
        ('share/ament_index/resource_index/packages', ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
        (os.path.join('share', package_name, 'launch'), glob('launch/*.py')),
        (os.path.join('share', package_name, 'config'), glob('config/*.yaml')),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='jesse',
    maintainer_email='a0970151287@gmail.com',
    description='ROS2 DDS network security monitor with LINE notification',
    license='Apache-2.0',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'monitor_node              = dds_security_monitor.monitor_node:main',
            'patrol_node               = dds_security_monitor.patrol_node:main',
            'sensor_hub_node           = dds_security_monitor.sensor_hub_node:main',
            'mission_manager           = dds_security_monitor.mission_manager_node:main',
            'system_status_node        = dds_security_monitor.system_status_node:main',
            'intelligent_defense_node  = dds_security_monitor.intelligent_defense_node:main',
        ],
    },
)
