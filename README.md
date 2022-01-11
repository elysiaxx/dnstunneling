# Content
## Description
This repo claim to run client program on windows as a client in dnstunneling scenario.
## Mode
- Downloading ( Done with narrow function) 
- Uploading ( Follow https://github.com/tbenbrahim/dns-tunneling-poc.git to get more info)
## Running
### Downloading
- Compile with cl compile tools of Visual Studio: 
- Command:
```
cl client.c
```
- Run: 
`client.exe --download test.txt [ip|domain] [ipaddress|domainname]`
- test.txt file will be save in ./data directory
### Uploading
This function is going on building.