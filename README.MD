# VX_Java_Infector

You can use this tool to patch java class files to include a call to your payload. 

## Requirements and installation

- Python 3.7+
- Clone or unpack Krakatau into the util folder (https://github.com/Storyyeller/Krakatau)

## Usage

### Calling the script

To call the script, use the following command:

```
python main.py
```

If all things are in in place, you should see your infected victims in the output folder. 

### tmp folder

Do not place any times in the tmp folder. The script places the jar and unpacks it in this folder. There are also other folders being used in order to place the class file and the java bytecode. 

### Java payload

You can use any self-written payload by placing the .class file of the payload into the 'payloads' folder. This payload must include the placeholder method with no variables. 

### Victim

You can place any .jar file into the victim folder. The tooling should be able to unpack it and patch the main class. 

Tested on
- Spring boot application
- Default JAR application

If your use case does not work, please leave behind an issue. 

### Output 

The script will place the infected files into the output folder. Running them using your local JRE should trigger the payload first.

## Theory

TBA