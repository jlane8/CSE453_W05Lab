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

# def is_homograph(sequence1, sequence2): 
#     if len(sequence1) < len(sequence2):
#         sequence2 = sequence2[(-len(sequence1)+1):]
#         sequence1 = sequence1[1:]
#         print(f"{sequence2=}")
#         print(f"{sequence1=}")
#         return canonicalize_sequence(sequence1) == canonicalize_sequence(sequence2)
#     if len(sequence2) < len(sequence1):
#         sequence1 = sequence1[(-len(sequence2)+1):]
#         sequence2 = sequence2[1:]
#         print(f"{sequence2=}")
#         print(f"{sequence1=}")
#         return canonicalize_sequence(sequence1) == canonicalize_sequence(sequence2)
    
def is_homograph(file_path, test_cases):
    """
    Splits up the test path so it can be iterated through and checks to see if it is 
    the same as the given file path. Then it will return whether or not they are 
    homographs.
    
    Keyword arguments:
    Perameters: file_path, test_cases
    Return: return_description
    """
    
    case_split = test_cases.split("/")
    new_list = []
    new_path = ""

    # Enumerates through the test path and compensates for special characters
    # ., .., and ~
    for i, string in enumerate(case_split):
        if string == ".." and i != 0:
            new_list.pop()
        elif string == "..":
            new_list = []
        elif i == 0 and string == ".":
            new_list.append("home")
        elif string == "~":
            new_list = []
            new_list.append("home")
        elif string != ".":
            new_list.append(string)

    # Creates a new path to be used for comparing against the given file path.
    for i, string in enumerate(new_list):
        if i < len(new_list) - 1:
            new_path += string + "/"
        else:
            new_path += string

    return canonicalize_sequence(file_path) == canonicalize_sequence(new_path)


def main():
    """
    This function will drive the program. It will request whether the user wishes to
    run automated or manual testing and respond accordingly. 
    Parameters: none
    Return:     nothing
    """
    # menu to either test automatically or select manual test
    # set selection to default to use as loop control
    selection = ""

    # loop until a valid selection is made
    while selection != "a" and selection != "m":

        # get selection from user
        selection = input("\nDo you want to run the (a)utomatic tests or input a path (m)anually a/m? ")
        
        # if automatic, run prepared test cases
        if selection == "a":
            test_cases(get_homographs(), "Homograph")
            test_cases(get_nonhomographs(), "Non-Homograph")

        # if manual, get arguments from user
        elif selection == "m":
            sequence1 = input("Specify the first filename: ")
            sequence2 = input("Specify the second filename: ")
            print(f"{sequence2=}")
            print(f"{sequence1=}")

            # Check if the sequences are homographs and show result
            if is_homograph(sequence1, sequence2):
                print("The sequences are homographs.")
            else:
                print("The sequences are not homographs.")

        # alert user to choose either automatic or manual and rerun selection
        else:
            print("Invalid choice. Please enter either a for automatic test or m for manual.")
    

# get list of homographs
def get_homographs():
    """
    This function will return a list of valid pathways and homograph pathways.
    Parameters: none
    Return:     homograph_testcases - a list of valid pathways and homographs
    """
    # set test cases for both homographs and non-homographs
    homograph_testcases = [
        ["home/cse453/week05/test.txt", "~/cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "./cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "./cse453/../cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "~/cse453/../../home/cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "../home/cse453/../cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "../home/../~/./cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "./cse453/./~/cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "~/cse453/./week05/test.txt"],
        ["home/cse453/week05/test.txt", "../home/./cse453/./week05/test.txt"],
        ["home/cse453/week05/test.txt", "~/../home/./cse453/week05/test.txt"],
        ["home/cse453/week05/test.txt", "./cse453/./week05/test.txt"]
    ]
    return homograph_testcases


# get list of non-homographs
def get_nonhomographs():
    """
    This function will return a list of valid pathways and non-homograph paths
    Parameters: none
    Return:     nonhomograph_testcases - a list of valid pathways and non-homograph paths
    """
    # set test cases that are non homographs
    nonhomograph_testcases = [
        ["home/cse453/week05/test.txt", "home/../cse453/week05/test.txt"]
    ]   
    return nonhomograph_testcases


# run test cases
def test_cases(tests, title):
    """
    This function will accept a list of valid and comparison pathways and a variable giving
    the title of the list. It will then loop through the list, calling the is_homograph function.
    It will display the result of that function and record the pass or fail result of the comparison
    to display at the end of the comparisons.
    Parameters: tests - a list of both valid pathways and paths to be compared against
                title - a string consisting of the title designating the tests list to be homograph
                        or non-homograph in nature
    Return:     nothing
    """
    # set defaults
    test_results = []
    result = ""

    # print header for display
    print("\n-----------------------------------------------------")
    print(f"{title} Comparisons:\n") 

    # loop through tests list with enumerate, determine whether the two are
    # homographs and display the result
    for item, homographs in enumerate(tests):
        result = is_homograph(homographs[0], homographs[1])
        print(f"Test Case {item + 1}: {homographs[0]} & {homographs[1]} = {result}")
        
        # if the two are homographs, show test as Passed, else False
        if result == True:
            test_result = "Passed"
        else:
            test_result = "Failed"

        # append results of test cases to the test_results list
        test_results.append(f"Test Case {item + 1}: {test_result}")
    
    # show definitive result of test cases
    print(f"\nFinal tally of {title} comparisons:\n")
    
    # loop through test results list
    for result in test_results:

        # if last 6 letters are failed, final result should be
        # 'not a homograph', otherwise it is 'a homograph' 
        if result[len(result)-6:] == "Failed":
            final_result = "not a homograph"
        else:
            final_result = "a homograph"

        # print the test case number, whether or not it is a homograph    
        print(f"{result}, so it is {final_result}.")

    # display footer to signify end of title test cases    
    print("\n-----------------------------------------------------\n")


if __name__ == "__main__":
    main()