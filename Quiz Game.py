from questions import quiz


def check_ans(question, ans, attempts, score):
    """
    Takes the arguments, and confirms if the answer provided by user is correct.
    Converts all answers to lower case to make sure the quiz is not case sensitive.
    """
    if quiz[question]['answer'].lower() == ans.lower():
        print(f"\nCorrect Answer! \n\nYour score is {score + 1}!\n\n")
        return True
    else:
        print(f"\nWrong Answer :( \nYou have {attempts - 1} left! \nTry again...\n")
        return False


def print_dictionary():
    for question_id, ques_answer in quiz.items():
        for key in ques_answer:
            print(key + ':', ques_answer[key])


def intro_message():
    """
    Introduces user to the quiz and rules, and takes an input from customer to start the quiz.
    Returns true regardless of any key pressed.
    """
    print("\nWelcome to my Intro to Cryptography quiz! \n\nAre you ready to test your knowledge about cryptography?")
    print("\nThere are a total of 20 questions, you can skip a question anytime by typing 'skip'")
    input("\nPress any key to start the fun ;)\n\n*********************************************\n")
    return True


# python project.py
intro = intro_message()
while True:
    score = 0
    for question in quiz:
        attempts = 3
        while attempts > 0:
            print(quiz[question]['question'])
            answer = input("\nEnter Answer (To move to the next question, type 'skip') : ")
            if answer == "skip":
                break
            check = check_ans(question, answer, attempts, score)
            if check:
                score += 1
                break
            attempts -= 1

    break

print(f"\nYour final score is {score}!\n\n")
print("Want to know the correct answers? Please see them below! ;)\n")
print_dictionary()
print("\nThanks for playing! 💜\n")
