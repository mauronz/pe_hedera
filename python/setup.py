from setuptools import setup, find_packages

setup(name='pe_hedera',
      version='0.1',
      packages=['pe_hedera'],
      package_data={'': ['pe_hedera.exe', 'leaf.dll']},
      include_package_data=True,
      install_requires=['pywin32']
      )