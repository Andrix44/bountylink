My bug bounty automation script.
Copy the project_template.yml file and edit it to set up your individual scans.
```
usage: bountylink.py [-h] [-l] projectfile

positional arguments:
  projectfile        The project configuration file (.yml)

optional arguments:
  -h, --help         show this help message and exit
  -l, --loaderdebug  Turns on debug logging before the configs are loaded. Will be overwritten afterwards
```
Included tools:
[amass](https://github.com/OWASP/Amass)
[eyewitness](https://github.com/FortyNorthSecurity/EyeWitness)
[takeover](https://github.com/m4ll0k/takeover)
