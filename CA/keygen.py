#!/usr/bin/python3.5
import os
import time
import root_keys
from time import sleep as wait
EntityName = input("Enter Entity/Auth Name:")
EntityName = EntityName.lower()
GroupName = input("Enter Group Name:")
GroupName = GroupName.lower()

if EntityName == "root":
    print('Invalid name. Entity/Auth name "root" not allowed')
    exit(1)

if os.popen("ls |grep "+EntityName).read() == EntityName:
    print("Folder named " + EntityName + " already exists")
    exit(2)
try:
    os.mkdir(EntityName)
except FileExistsError as e:
    print("Entity already exists.")
    print("Error: %s" %e)
    exit(3)

root_modulus = root_keys.modulus

# public exponent is constant and hence never shared
public_expo = 0x10001

os.popen("openssl genrsa -out %s/private.pem -f4 1024" % EntityName).read()
wait(1)
modulus = 1<<1024
while modulus>root_keys.modulus:
    cert = os.popen("openssl rsa -in ./%s/private.pem -text -noout" % EntityName).read()
    if not cert:
        print("Some error occurred while generating cert using openssl")
        os.rmdir(EntityName)
        exit(4)
    modulus = cert.split('modulus:')[1].split("publicExponent")[0]
    modulus = int(modulus.replace(' ', '').replace('\n', '').replace(':', ''),16)
    #print(hex(modulus))

    privet_expo = cert.split("privateExponent:")[1].split("prime1:")[0]
    privet_expo = int(privet_expo.replace(' ', '').replace('\n', '').replace(':', ''),16)
    # print(hex(privet_expo))


entity_cert = pow(modulus, root_keys.private_expo, root_keys.modulus)

# Generating python file with all variables
python_file = open(EntityName + "/rsa_keys.py", "w")
python_file.write(
                '''
#This file generated for Entityname : "%s" and GroupName : "%s"
#This file is required only if entity runs on python\n
modulus = %s \n
private_expo = %s\n
cert = %s\n
root_modulus = %s\n
public_expo = %s\n\n''' %
        (EntityName,
         GroupName,
         hex(modulus),
         hex(privet_expo),
         hex(entity_cert),
         hex(root_modulus),
         hex(public_expo)))
python_file.close()

# Generating C file with all variables
c_file = open(EntityName + "/rsa_keys.c", "w")
c_file.write(
            '''/********************************************************************
* This file generated for Entityname : "%s" and GroupName : "%s"
* This file is required only if entity runs embedded device using C
* Variable of this file can be used as extern in main program
* This has no include pri-processing 
*********************************************************************/\n
''' % (EntityName, GroupName))
# writing modulus in c file
c_file.write("const char modulus[128] = {")
x = modulus
for i in range(0, 8):
    for j in range(0, 16):
        y = (x >> (1024-8)) & 0xff
        c_file.write(" %s," % hex(y))
        x = x << 8
    c_file.write("\n                           ")
c_file.write("};\n\n")

# writing privet_expo in c file
c_file.write("const char privet_expo[128] = {")
x = privet_expo
for i in range(0, 8):
    for j in range(0, 16):
        y = x >> (1024-8) & 0xff
        c_file.write(" %s," % hex(y))
        x = x << 8
    c_file.write("\n                               ")
c_file.write("};\n\n")

# writing entity_cert in c file
c_file.write("const char cert[128] = {")
x = entity_cert
for i in range(0, 8):
    for j in range(0, 16):
        y = x >> (1024-8) & 0xff
        c_file.write(" %s," % hex(y))
        x = x << 8
    c_file.write("\n                        ")
c_file.write("};\n\n")

# writing root_modulus in c file
c_file.write("const char root_modulus[128] = {")
x = root_modulus
for i in range(0, 8):
    for j in range(0, 16):
        y = x >> (1024-8) & 0xff
        c_file.write(" %s," % hex(y))
        x = x << 8
    c_file.write("\n                                ")
c_file.write("};\n\n")

# writing public_expo in c file
c_file.write("const char public_expo[128] = {")
x = public_expo
for i in range(0, 8):
    for j in range(0, 16):
        y = x >> (1024-8) & 0xff
        c_file.write(" %s," % hex(y))
        x = x << 8
    c_file.write("\n                               ")
c_file.write("};\n\n")
c_file.close()

print("Entity/Auth certificate and file generation completed successfully")
print("Generated files:")
print("\t%s/rsa_keys.py" % EntityName)
print("\t%s/rsa_keys.c" % EntityName)
print("exiting from program...")
exit(0)
