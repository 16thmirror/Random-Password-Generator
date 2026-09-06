import random
import string

length = int(input("How long do you want your password to be? "))

characters = string.ascii_letters + string.digits + string.punctuation
password = ''.join(random.choice(characters) for _ in range(length))

print(f"Your generated password is: {password}")