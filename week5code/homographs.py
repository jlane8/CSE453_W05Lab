#One common form of the homograph attack is for the attacker to attempt to access a forbidden resource, such as a file on a filesystem, by specifying a different file sequence from what the 
# programmer of an application intended. The programmer may attempt to prevent such requests by creating a block list of forbidden files. The problem arises when the attacker finds a way 
# to specify the forbidden file in a way that circumvents the block list. This is done, of course, with a homograph attack.

# Your task is to write a program to prompt the user for a file sequence. Compare this sequence against a second file sequence, which will represent the sequence to a forbidden file 
# such as secret/password.txt. Display whether these two sequences are the same or whether they refer to different resources. To do this, research what types of symbols are available on your 
# command shell, demonstrate code that is vulnerable to the homograph attack, and write code that detects sequence homographs. An example of the program execution might be:

# </home/cse453/week05> lab05.out
# Specify the first filename:  test.txt
# Specify the second filename: ../../cse453/week05/test.txt
# The sequences are homographs

# Note 1: Whether the two sequences represent the same resource sometimes depends on the current working directory.
# Note 2: You do not need to access the actual filesystem for this lab. Your should simply ask the user for two different file sequences, then compare those sequences to determine whether 
# they represent the same resource.

# sequence Symbols: There are many ways to specify a sequence to a given file system resource. Your specific file system (be that Windows, Macintosh, or Linux) provides a rich set of symbols 
# to help with this. Some include slashes (/ for Macintosh and Linux, \ for Windows), single dots (.) to indicate the current directory, and double dot (..) to indicate the previous 
# directory. On Windows, the drive letter followed by a colon is also used (C:, D:, etc).

# def homograph_analyser(sequence):
#     sim_list = {"0x68": ["FF48", "04BB", "0x68"], # h
#                 "0065": ["0065", "0435", "FF45"]} # e
#     cannon = ""
#     keys = []
#     for char in sequence:
#         char_hex = hex(ord(char))
#         values = sim_list.values()
#         index = 0
#         for key in values:
#             print(f"key:{key}")
#             print(f"values:{values}")
#             if char_hex in key:
#                 print("Char in key list")
#                 sim_list[index] += keys
#             else: 
#                 index +=1 
#                 print(f"index: {index}")
#             #print("IN SIM LIST")
#         # for key in sim_list:
#             # if sim_list[key[2:3]] == char_hex[2:3]:
#             #     converted_hex = bytearray.fromhex(char_hex).decode()
#             #     print(converted_hex)
#             #     cannon += converted_hex
#             #     print(cannon)
#         print("DONE")

import unicodedata

def canonicalize_sequence(sequence):
    # print("canonicalize_sequence")
    canon = unicodedata.normalize('NFKC', sequence)
    canon = canon.lower()
    # print(canon)
    return canon

def is_homograph(sequence1, sequence2): 
    if len(sequence1) < len(sequence2):
        sequence2 = sequence2[(-len(sequence1)+1):]
        sequence1 = sequence1[1:]
        # print(f"{sequence2=}")
        # print(f"{sequence1=}")
        return canonicalize_sequence(sequence1) == canonicalize_sequence(sequence2)
    if len(sequence2) < len(sequence1):
        sequence1 = sequence1[(-len(sequence2)+1):]
        sequence2 = sequence2[1:]
        # (f"{sequence2=}")
        # (f"{sequence1=}")
        return canonicalize_sequence(sequence1) == canonicalize_sequence(sequence2)

def main():
    # sequence1 = "hello"
    # sequence2 = "HELLO"
    # homograph_analyser(sequence1)
    # homograph_analyser(sequence2)
    
    sequence1 = input("Specify the first filename: ")
    sequence2 = input("Specify the second filename: ")
    print(f"{sequence2=}")
    print(f"{sequence1=}")
    
    # Check if the sequences are homographs
    if is_homograph(sequence1, sequence2):
        print("The sequences are homographs.")
    else:
        print("The sequences are not homographs.")
    


testcases = []   
#TEST CASES
def test_case1():
    print("-----------------------------------------------------") 
    print("TEST CASE 1")
    sequence1 = "TESTING.txt"
    print("Specify the first filename: TESTING.txt")
    sequence2 = "../../cse453/week05/test.txt"
    print("Specify the second filename: ../../cse453/week05/test.txt")
    is_homograph_bool = is_homograph(sequence1, sequence2)
    # Check if the sequences are homographs
    if is_homograph_bool:
        print("The sequences are homographs.")
    else:
        print("The sequences are not homographs.")
    if is_homograph_bool == False:
        testcases.append("Test case 1: PASSED")
    if is_homograph_bool == True:
        testcases.append("Test Case 1: NOT PASSED.")
    print("-----------------------------------------------------")
        
def test_case2():
    print("TEST CASE 2")
    sequence1 = "test.txt"
    print("Specify the first filename: test.txt")
    sequence2 = "../../cse453/week05/test.txt"
    print("Specify the second filename: ../../cse453/week05/test.txt")
    is_homograph_bool = is_homograph(sequence1, sequence2)
    # Check if the sequences are homographs
    if is_homograph_bool:
        print("The sequences are homographs.")
    else:
        print("The sequences are not homographs.")
    if is_homograph_bool == True:
        testcases.append("Test case 2: PASSED")
    if is_homograph_bool == False:
        testcases.append("Test Case 2: NOT PASSED.")
    print("-----------------------------------------------------") 
      
def test_case3():
    print("TEST CASE 3")
    sequence1 = "TEST.txt"
    print("Specify the first filename: TEST.txt")
    sequence2 = "../../cse453/week05/test.txt"
    print("Specify the second filename: ../../cse453/week05/test.txt")
    is_homograph_bool = is_homograph(sequence1, sequence2)
    # Check if the sequences are homographs
    if is_homograph_bool:
        print("The sequences are homographs.")
    else:
        print("The sequences are not homographs.")
    if is_homograph_bool == True:
        testcases.append("Test case 3: PASSED")
    if is_homograph_bool == False:
        testcases.append("Test Case 3: NOT PASSED.")
    print("-----------------------------------------------------")
        
def test_case4():
    print("TEST CASE 4")
    sequence1 = "TEST.tⅩt"
    print("Specify the first filename: test.tⅩt")
    sequence2 = "../../cse453/week05/test.txt"
    print("Specify the second filename: ../../cse453/week05/test.txt")
    is_homograph_bool = is_homograph(sequence1, sequence2)
    # Check if the sequences are homographs
    if is_homograph_bool:
        print("The sequences are homographs.")
    else:
        print("The sequences are not homographs.")
    if is_homograph_bool == True:
        testcases.append("Test case 4: PASSED")
    if is_homograph_bool == False:
        testcases.append("Test Case 4: NOT PASSED.")
    print("-----------------------------------------------------") 

def test_case5():
    print("TEST CASE 5")
    sequence1 = "home/user/secret/"
    print("Specify the first filename: home/user/secret/")
    sequence2 = "~/user/secret/"
    print("Specify the second filename: ~/user/secret/")
    is_homograph_bool = is_homograph(sequence1, sequence2)
    # Check if the sequences are homographs
    if is_homograph_bool:
        print("The sequences are homographs.")
    else:
        print("The sequences are not homographs.")
    if is_homograph_bool == True:
        testcases.append("Test case 5: PASSED")
    if is_homograph_bool == False:
        testcases.append("Test Case 5: NOT PASSED.")
    print("-----------------------------------------------------") 
    
print("-----------------------------------------------------")
print("NON-HOMOGRAPHS")             
test_case1()
print("HOMOGRAPHS")
print("-----------------------------------------------------")
test_case2()
test_case3()
test_case4()
test_case5()

for test in testcases:
    print(test)
print("-----------------------------------------------------") 
if __name__ == "__main__":
    main()