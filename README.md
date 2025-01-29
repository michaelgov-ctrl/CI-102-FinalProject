DISCLAIMER: this project is for educational purposes only.

[![A demonstration using the package can be found here](https://img.youtube.com/vi/pMo5FckCh8E/0.jpg)](https://youtu.be/pMo5FckCh8E)
The first project for CI 102 is to create a presentation regarding a cyber security topic.

My team chose the ransomware™. To provide a brief example of the functionality of ransomware™ I've written a program that will either recursively encrypt or decrypt a target directory.

[usage]

-encrypt:
    Pass to encrypt data

-target_directories string:
    [required] Comma-separated list of directories to encrypt

-worker_count int:
    Number of workers to encrypt/decrpyt with (default 5)