#One common form of the homograph attack is for the attacker to attempt to access a forbidden resource, such as a file on a filesystem, by specifying a different file path from what the 
# programmer of an application intended. The programmer may attempt to prevent such requests by creating a block list of forbidden files. The problem arises when the attacker finds a way 
# to specify the forbidden file in a way that circumvents the block list. This is done, of course, with a homograph attack.

# Your task is to write a program to prompt the user for a file path. Compare this path against a second file path, which will represent the path to a forbidden file 
# such as secret/password.txt. Display whether these two paths are the same or whether they refer to different resources. To do this, research what types of symbols are available on your 
# command shell, demonstrate code that is vulnerable to the homograph attack, and write code that detects path homographs. An example of the program execution might be:

# </home/cse453/week05> lab05.out
# Specify the first filename:  test.txt
# Specify the second filename: ../../cse453/week05/test.txt
# The paths are homographs

# Note 1: Whether the two paths represent the same resource sometimes depends on the current working directory.
# Note 2: You do not need to access the actual filesystem for this lab. Your should simply ask the user for two different file paths, then compare those paths to determine whether 
# they represent the same resource.

# Path Symbols: There are many ways to specify a path to a given file system resource. Your specific file system (be that Windows, Macintosh, or Linux) provides a rich set of symbols 
# to help with this. Some include slashes (/ for Macintosh and Linux, \ for Windows), single dots (.) to indicate the current directory, and double dot (..) to indicate the previous 
# directory. On Windows, the drive letter followed by a colon is also used (C:, D:, etc).

def homograph_analyser(sequence):
    sim_list = {"0x68": ["FF48", "04BB", "0x68"], # h
                "0065": ["0065", "0435", "FF45"]} # e
    cannon = ""
    keys = []
    for char in sequence:
        char_hex = hex(ord(char))
        values = sim_list.values()
        index = 0
        for key in values:
            print(f"key:{key}")
            print(f"values:{values}")
            if char_hex in key:
                print("Char in key list")
                sim_list[index] += keys
            else: 
                index +=1 
                print(f"index: {index}")
            #print("IN SIM LIST")
        # for key in sim_list:
            # if sim_list[key[2:3]] == char_hex[2:3]:
            #     converted_hex = bytearray.fromhex(char_hex).decode()
            #     print(converted_hex)
            #     cannon += converted_hex
            #     print(cannon)
        print("DONE")


def main():
    sequence1 = "hello"
    sequence2 = "HELLO"
    homograph_analyser(sequence1)
    homograph_analyser(sequence2)
    
    
main()