import secrets
import string

# Single SystemRandom instance reused for all cryptographic operations
_rng = secrets.SystemRandom()

AMBIGUOUS_CHARS = "il1LoO0|`'\";:,."


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
        The generated password as a string.
    """
    categories = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    ]

    if exclude_ambiguous:
        categories = [
            "".join(c for c in cat if c not in AMBIGUOUS_CHARS)
            for cat in categories
        ]

    # Guarantee at least one character from each category
    password_chars = [_rng.choice(cat) for cat in categories]

    # Fill the remaining length from the full combined pool
    all_chars = "".join(categories)
    password_chars.extend(
        _rng.choice(all_chars) for _ in range(length - len(password_chars))
    )

    _rng.shuffle(password_chars)
    return "".join(password_chars)


def _prompt_length(minimum: int = 8) -> int:
    while True:
        try:
            length = int(input(f"Enter password length (minimum {minimum}): "))
            if length < minimum:
                print(f"Length must be at least {minimum} for baseline security.")
                continue
            return length
        except ValueError:
            print("Please enter a valid whole number.")


def _prompt_yes_no(question: str) -> bool:
    answer = input(f"{question} (y/n): ").strip().lower()
    return answer.startswith("y")


def main() -> None:
    length = _prompt_length()
    exclude_ambiguous = _prompt_yes_no(
        "Exclude ambiguous characters like l, 1, I, O, 0?"
    )
    password = generate_password(length, exclude_ambiguous=exclude_ambiguous)
    print(f"Your generated password is: {password}")


if __name__ == "__main__":
    main()
