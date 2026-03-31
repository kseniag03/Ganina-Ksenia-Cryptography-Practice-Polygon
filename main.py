
"""
Практическая работа №2: подстановочные шифры (Python)

Реализованы:
1) шифр простой замены;
2) аффинный шифр;
3) аффинный рекуррентный шифр.

Программа:
- принимает текст от пользователя;
- принимает ключ, соответствующий выбранному шифру;
- выполняет шифрование или расшифрование по выбору пользователя.

Зафиксированные параметры для быстрых тестов:
- alphabet = ABCDEFGHIJKLMNOPQRSTUVWXYZ
- substitution key = OQJTVDMAUEPNXRSWGYILKCFZHB
- affine key = (5, 8)
- recurrent affine initial keys = (5, 8) и (7, 3)

Тестовое слово для проверки: WIZARD
"""


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DEFAULT_SUBSTITUTION_KEY = "OQJTVDMAUEPNXRSWGYILKCFZHB"
DEFAULT_A = 5
DEFAULT_B = 8
DEFAULT_A1 = 5
DEFAULT_B1 = 8
DEFAULT_A2 = 7
DEFAULT_B2 = 3
DEMO_WORD = "WIZARD"


def gcd(a, b):
    if b == 0:
        return abs(a)

    return gcd(b, a % b)


def prepare_text(text: str) -> str:
    """
    Приводит текст к верхнему регистру.
    Символы, отсутствующие в алфавите, не удаляются: программа принимает произвольную последовательность символов, но шифрует только те, что входят в выбранный алфавит.
    """
    return text.upper()


def validate_alphabet(alphabet: str) -> None:
    if not alphabet:
        raise ValueError("Алфавит не должен быть пустым.")

    if len(set(alphabet)) != len(alphabet):
        raise ValueError("Алфавит не должен содержать повторяющиеся символы.")


def validate_substitution_key(alphabet: str, key: str) -> str:
    key = key.upper().strip()
    validate_alphabet(alphabet)

    if len(key) != len(alphabet):
        raise ValueError(f"Ключ простой замены должен иметь длину {len(alphabet)} символов.")

    if set(key) != set(alphabet):
        raise ValueError("Ключ простой замены должен быть перестановкой символов выбранного алфавита.")

    return key


def encrypt_substitution(text: str, alphabet: str, key: str) -> str:
    key = validate_substitution_key(alphabet, key)
    prepared = prepare_text(text)
    mapping = {alphabet[i]: key[i] for i in range(len(alphabet))}

    return "".join(mapping.get(ch, ch) for ch in prepared)


def decrypt_substitution(text: str, alphabet: str, key: str) -> str:
    key = validate_substitution_key(alphabet, key)
    prepared = prepare_text(text)
    reverse_mapping = {key[i]: alphabet[i] for i in range(len(alphabet))}

    return "".join(reverse_mapping.get(ch, ch) for ch in prepared)


def mod_inverse(a: int, m: int) -> int:
    """
    Возвращает обратный элемент a^(-1) по модулю m.
    Используется расширенный алгоритм Евклида.
    """
    if gcd(a, m) != 1:
        raise ValueError(f"Элемент a={a} не имеет обратного по модулю {m}, так как gcd(a, m) != 1.")

    old_r, r = a, m
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    return old_s % m


def validate_affine_key(a: int, b: int, m: int) -> tuple[int, int]:
    if gcd(a, m) != 1:
        raise ValueError(
            f"Недопустимый ключ: gcd(a={a}, m={m}) != 1. "
            "Для аффинного шифра коэффициент a должен быть взаимно прост с мощностью алфавита."
        )

    return a % m, b % m


def encrypt_affine(text: str, alphabet: str, a: int, b: int) -> str:
    validate_alphabet(alphabet)
    prepared = prepare_text(text)
    m = len(alphabet)
    a, b = validate_affine_key(a, b, m)

    result = []

    for ch in prepared:
        if ch in alphabet:
            x = alphabet.index(ch)
            y = (a * x + b) % m
            result.append(alphabet[y])
        else:
            result.append(ch)

    return "".join(result)


def decrypt_affine(text: str, alphabet: str, a: int, b: int) -> str:
    validate_alphabet(alphabet)
    prepared = prepare_text(text)
    m = len(alphabet)
    a, b = validate_affine_key(a, b, m)
    a_inv = mod_inverse(a, m)

    result = []

    for ch in prepared:
        if ch in alphabet:
            y = alphabet.index(ch)
            x = (a_inv * (y - b)) % m
            result.append(alphabet[x])
        else:
            result.append(ch)

    return "".join(result)


def generate_recurrent_keys(a1: int, b1: int, a2: int, b2: int, text_len: int, m: int) -> list[tuple[int, int]]:
    """
    Формирует список ключевых пар для аффинного рекуррентного шифра:
    (a1, b1), (a2, b2),
    a_i = (a_{i-1} * a_{i-2}) mod m
    b_i = (b_{i-1} + b_{i-2}) mod m
    """
    if text_len <= 0:
        return []

    a1, b1 = validate_affine_key(a1, b1, m)
    a2, b2 = validate_affine_key(a2, b2, m)

    keys = [(a1, b1)]

    if text_len == 1:
        return keys

    keys.append((a2, b2))

    while len(keys) < text_len:
        prev2 = keys[-2]
        prev1 = keys[-1]
        next_a = (prev1[0] * prev2[0]) % m
        next_b = (prev1[1] + prev2[1]) % m

        if gcd(next_a, m) != 1:
            raise ValueError(
                f"На шаге {len(keys)+1} получен недопустимый коэффициент a={next_a}: "
                f"gcd({next_a}, {m}) != 1. Выберите другие начальные ключевые пары."
            )

        keys.append((next_a, next_b))

    return keys


def encrypt_affine_recurrent(text: str, alphabet: str, a1: int, b1: int, a2: int, b2: int) -> str:
    validate_alphabet(alphabet)
    prepared = prepare_text(text)
    m = len(alphabet)

    symbol_count = sum(1 for ch in prepared if ch in alphabet)
    keys = generate_recurrent_keys(a1, b1, a2, b2, symbol_count, m)

    result = []
    key_index = 0

    for ch in prepared:
        if ch in alphabet:
            a_i, b_i = keys[key_index]
            x = alphabet.index(ch)
            y = (a_i * x + b_i) % m
            result.append(alphabet[y])
            key_index += 1
        else:
            result.append(ch)

    return "".join(result)


def decrypt_affine_recurrent(text: str, alphabet: str, a1: int, b1: int, a2: int, b2: int) -> str:
    validate_alphabet(alphabet)
    prepared = prepare_text(text)
    m = len(alphabet)

    symbol_count = sum(1 for ch in prepared if ch in alphabet)
    keys = generate_recurrent_keys(a1, b1, a2, b2, symbol_count, m)

    result = []
    key_index = 0

    for ch in prepared:
        if ch in alphabet:
            a_i, b_i = keys[key_index]
            a_inv = mod_inverse(a_i, m)
            y = alphabet.index(ch)
            x = (a_inv * (y - b_i)) % m
            result.append(alphabet[x])
            key_index += 1
        else:
            result.append(ch)

    return "".join(result)


def parse_two_ints(raw: str) -> tuple[int, int]:
    parts = raw.replace(",", " ").split()

    if len(parts) != 2:
        raise ValueError("Нужно ввести ровно два целых числа.")

    return int(parts[0]), int(parts[1])


def parse_four_ints(raw: str) -> tuple[int, int, int, int]:
    parts = raw.replace(",", " ").split()

    if len(parts) != 4:
        raise ValueError("Нужно ввести ровно четыре целых числа: a1 b1 a2 b2.")

    return int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])


def print_fixed_parameters_info() -> None:
    print("\nЗафиксированные параметры для быстрых тестов:")
    print(f"\tАлфавит: {ALPHABET}")
    print(f"\tКлюч простой замены: {DEFAULT_SUBSTITUTION_KEY}")
    print(f"\tАффинный ключ: a={DEFAULT_A}, b={DEFAULT_B}")
    print(f"\tАффинный рекуррентный ключ: (a1, b1)=({DEFAULT_A1}, {DEFAULT_B1}), (a2, b2)=({DEFAULT_A2}, {DEFAULT_B2})")


def choose_cipher() -> str:
    print("Выберите шифр:")
    print("\t1 - Простая замена")
    print("\t2 - Аффинный")
    print("\t3 - Аффинный рекуррентный")
    cipher = input("Введите номер шифра: ").strip()

    if cipher not in {"1", "2", "3"}:
        raise ValueError("Некорректный номер шифра.")

    return cipher


def choose_mode() -> str:
    print("\nВыберите режим:")
    print("\t1 - Шифрование")
    print("\t2 - Расшифрование")
    mode = input("Введите номер режима: ").strip()

    if mode not in {"1", "2"}:
        raise ValueError("Некорректный номер режима.")

    return mode


def ask_text() -> str:
    raw_text = input("\nВведите текст: ")
    prepared = prepare_text(raw_text)

    if not prepared:
        raise ValueError("Текст не должен быть пустым.")
    if not any(ch in ALPHABET for ch in prepared):
        raise ValueError("В тексте нет ни одного символа из выбранного алфавита.")

    return prepared


def ask_substitution_key() -> str:
    print(f"\nВведите ключ-перестановку длиной 26 символов или нажмите Enter для значения по умолчанию:\n{DEFAULT_SUBSTITUTION_KEY}")
    raw = input("Ключ: ").strip().upper()

    if raw == "":
        raw = DEFAULT_SUBSTITUTION_KEY

    return validate_substitution_key(ALPHABET, raw)


def ask_affine_key() -> tuple[int, int]:
    print(f"\nВведите ключ a b через пробел или нажмите Enter для значения по умолчанию: {DEFAULT_A} {DEFAULT_B}")
    raw = input("Ключ: ").strip()

    if raw == "":
        return validate_affine_key(DEFAULT_A, DEFAULT_B, len(ALPHABET))

    a, b = parse_two_ints(raw)

    return validate_affine_key(a, b, len(ALPHABET))


def ask_recurrent_key() -> tuple[int, int, int, int]:
    print(f"\nВведите ключи a1 b1 a2 b2 через пробел или нажмите Enter для значения по умолчанию: {DEFAULT_A1} {DEFAULT_B1} {DEFAULT_A2} {DEFAULT_B2}")
    raw = input("Ключ: ").strip()

    if raw == "":
        return DEFAULT_A1, DEFAULT_B1, DEFAULT_A2, DEFAULT_B2

    return parse_four_ints(raw)


def run_interactive() -> None:
    print("Практическая работа №2: простые подстановочные шифры")
    print_fixed_parameters_info()

    while True:
        try:
            cipher = choose_cipher()
            mode = choose_mode()
            text = ask_text()

            if cipher == "1":
                key = ask_substitution_key()

                if mode == "1":
                    result = encrypt_substitution(text, ALPHABET, key)
                else:
                    result = decrypt_substitution(text, ALPHABET, key)

            elif cipher == "2":
                a, b = ask_affine_key()

                if mode == "1":
                    result = encrypt_affine(text, ALPHABET, a, b)
                else:
                    result = decrypt_affine(text, ALPHABET, a, b)

            else:
                a1, b1, a2, b2 = ask_recurrent_key()

                if mode == "1":
                    result = encrypt_affine_recurrent(text, ALPHABET, a1, b1, a2, b2)
                else:
                    result = decrypt_affine_recurrent(text, ALPHABET, a1, b1, a2, b2)

            print(f"\nРезультат: {result}")

        except Exception as ex:
            print(f"\nОшибка: {ex}")

        repeat = input("\nВыполнить ещё одну операцию? (y/n): ").strip().lower()

        if repeat != "y":
            print("Завершение программы.")
            break


def show_demo() -> None:
    print(f"\nДемонстрация на слове {DEMO_WORD}")
    print("-" * 50)

    sub_enc = encrypt_substitution(DEMO_WORD, ALPHABET, DEFAULT_SUBSTITUTION_KEY)
    sub_dec = decrypt_substitution(sub_enc, ALPHABET, DEFAULT_SUBSTITUTION_KEY)
    print("Простая замена:")
    print(f"\tОткрытый текст:   {DEMO_WORD}")
    print(f"\tШифртекст:        {sub_enc}")
    print(f"\tРасшифрование:    {sub_dec}")

    aff_enc = encrypt_affine(DEMO_WORD, ALPHABET, DEFAULT_A, DEFAULT_B)
    aff_dec = decrypt_affine(aff_enc, ALPHABET, DEFAULT_A, DEFAULT_B)
    print("\nАффинный шифр:")
    print(f"\tОткрытый текст:   {DEMO_WORD}")
    print(f"\tШифртекст:        {aff_enc}")
    print(f"\tРасшифрование:    {aff_dec}")

    rec_enc = encrypt_affine_recurrent(DEMO_WORD, ALPHABET, DEFAULT_A1, DEFAULT_B1, DEFAULT_A2, DEFAULT_B2)
    rec_dec = decrypt_affine_recurrent(rec_enc, ALPHABET, DEFAULT_A1, DEFAULT_B1, DEFAULT_A2, DEFAULT_B2)
    print("\nАффинный рекуррентный шифр:")
    print(f"\tОткрытый текст:   {DEMO_WORD}")
    print(f"\tШифртекст:        {rec_enc}")
    print(f"\tРасшифрование:    {rec_dec}")

    print("-" * 50)


if __name__ == "__main__":
    # Сначала выводит готовый пример на слове WIZARD, затем запускает интерактивный режим.
    show_demo()
    run_interactive()
