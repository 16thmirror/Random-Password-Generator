import secrets
import string

# Single SystemRandom instance reused for all cryptographic operations
_rng = secrets.SystemRandom()

AMBIGUOUS_CHARS = "il1LoO0|`'\";:,."
_STRIP_AMBIGUOUS = str.maketrans("", "", AMBIGUOUS_CHARS)

def generate_password(length: int, exclude_ambiguous: bool = False) -> str:
    
    """Generate a cryptographically secure random password.

    Guarantees at least one lowercase letter, one uppercase letter,
    one digit, and one punctuation character.
    Args:
        length: Desired password length (must be at least 4 to fit
            one character from each category).
        exclude_ambiguous: If True, removes easily confused characters
            (e.g. l, 1, I, O, 0) from the character pool.
    Returns:
        The generated password as a string."""
    
    categories = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    ]

    if exclude_ambiguous:
        categories = [cat.translate(_STRIP_AMBIGUOUS) for cat in categories]

    # Guarantee at least one character from each category, then fill the
    # rest of the length from the combined pool of all categories.
    password_chars = [_rng.choice(cat) for cat in categories]
    all_chars = "".join(categories)
    password_chars.extend(_rng.choices(all_chars, k=length - len(password_chars)))

    _rng.shuffle(password_chars)
    return "".join(password_chars)

def _prompt_length(minimum: int = 8) -> int:
    while True:
        try:
            length = int(input(f"Enter password length (minimum {minimum}): "))
        except ValueError:
            print("Please enter a valid whole number.")
            continue
        if length < minimum:
            print(f"Length must be at least {minimum} for baseline security.")
            continue
        return length

def _prompt_yes_no(question: str) -> bool:
    return input(f"{question} (y/n): ").strip().lower().startswith("y")

def main() -> None:
    length = _prompt_length()
    exclude_ambiguous = _prompt_yes_no(
        "Exclude ambiguous characters like l, 1, I, O, 0?"
    )
    password = generate_password(length, exclude_ambiguous=exclude_ambiguous)
    print(f"Your generated password is: {password}")

if __name__ == "__main__":
    main()
