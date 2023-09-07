from setuptools import setup, find_packages

with open("requirements.txt") as fp:
    install_requires = fp.read()

setup(
    name="sps-contact-lambda",
    version="0.0.1",
    author="Levi Muniz",
    author_email="levi.muniz17@gmail.com",
    url="https://github.com/Snowy-Peak-Systems/contact-lambda",
    description="AWS Lambda that sends an email when a request is received",
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(),
    test_suite="tests",
    install_requires=install_requires,
)
