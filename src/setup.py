from setuptools import setup, find_packages
import os

install_requires = [
    "crc16==0.1.1","pysha3==1.0.2", "pgpy==0.5.2", "phe==1.4.0"
]

test_requires = [
     "mock", "xmlrunner", "coverage"
]

setup(name='cryptolib',
      version='0.3',
      description='General purpose crypto library',
      author='Coinplus',
      author_email='info@coinplus.com',
      packages=find_packages(),
      install_requires=install_requires,
      tests_require=test_requires,
      package_data={
          "cryptolib": ["openssl/*.dll"],
          "cryptolib": ["openssl/*.so.1.0.0"],
          "cryptolib": ["TSS.Net.dll", "GetRandom.exe"]
      },
      include_package_data=True
      )



