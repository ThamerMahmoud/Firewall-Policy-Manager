import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="example-pkg-your-username",
    version="0.0.1",
    author="Thamer Mahmoud",
    author_email="thamer84@gmail.com",
    description="Firewall policy Manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ThamerMahmoud/Firewall-Policy-Manager/blob/master/",
    packages=setuptools.find_packages(),
	# packages= ['paramiko', 'netaddr' , ''],
	install_requires=[
          'paramiko',  ],
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
