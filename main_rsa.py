
"""
Практическая работа: криптосистема RSA (Python)

Реализованы:
1) генерация ключевой пары RSA с использованием больших чисел;
2) шифрование и расшифрование текста из файла или строки;
3) ввод открытого и закрытого ключа вручную;
4) атака Ферма на RSA для случая малого модуля и близких простых множителей p и q.

Программа:
- принимает текст от пользователя;
- принимает ключ, соответствующий выбранному шифру;
- выполняет шифрование или расшифрование по выбору пользователя.

Стандартные модули Python используются только для вспомогательных операций.
Готовые реализации RSA и криптографических преобразований не применяются.

Зафиксированные параметры для быстрых тестов: (p, q, e) = (61, 53, 17),
и для демонстрации на больших числах: (bits, e, fermat_rounds) = (64, 65537, 16)

Тестовое слово для проверки: WIZARD
"""


import math
import secrets
from dataclasses import dataclass
from pathlib import Path


DEMO_P = 61
DEMO_Q = 53
DEMO_E = 17
DEFAULT_PRIME_BITS = 64
DEFAULT_E = 65537
FERMAT_TEST_ROUNDS = 16
DEMO_WORD = "WIZARD"


@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int


@dataclass
class FullKeyPair:
    public: PublicKey
    private: PrivateKey
    p: int
    q: int
    phi: int


def gcd(a, b):
    if b == 0:
        return abs(a)

    return gcd(b, a % b)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Расширенный алгоритм Евклида.
    Возвращает gcd(a, b), x, y такие, что a*x + b*y = gcd(a, b).
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Возвращает обратный элемент a^(-1) по модулю m."""
    g, x, _ = extended_gcd(a, m)

    if g != 1:
        raise ValueError(f"Число {a} не имеет обратного элемента по модулю {m}, так как gcd != 1.")
    
    return x % m


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Быстрое возведение в степень по модулю методом повторного возведения в квадрат.
    Используется вместо готового pow(base, exponent, modulus).
    """
    if modulus <= 0:
        raise ValueError("Модуль должен быть положительным числом.")

    if exponent < 0:
        raise ValueError("Показатель степени должен быть неотрицательным.")

    result = 1
    base %= modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent //= 2

    return result


def is_probable_prime_fermat(n: int, rounds: int = FERMAT_TEST_ROUNDS) -> bool:
    """
    Вероятностная проверка числа на простоту на основе малой теоремы Ферма.
    Метод подходит для учебной демонстрации, но не используется как единственная
    проверка простоты в промышленной криптографии, поскольку существуют составные
    числа, проходящие тест Ферма (псевдопростые числа и числа Кармайкла).
    """
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    if n in small_primes:
        return True

    if any(n % p == 0 for p in small_primes):
        return False

    # для n > 3 проверяем несколько случайных оснований a: a^(n-1) == 1 (mod n).
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # диапазон [2; n - 2]

        if gcd(a, n) != 1:
            return False
        
        if mod_pow(a, n - 1, n) != 1:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Генерирует вероятно простое нечетное число заданной битовой длины."""
    if bits < 8:
        raise ValueError("Битовая длина простого числа должна быть не меньше 8.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= 1                      # число должно быть нечетным
        candidate |= 1 << (bits - 1)        # старший бит фиксируется, чтобы длина была равна bits

        if is_probable_prime_fermat(candidate):
            return candidate


def generate_key_pair(prime_bits: int = DEFAULT_PRIME_BITS, e: int = DEFAULT_E) -> FullKeyPair:
    """Генерирует ключевую пару RSA."""
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            continue

        d = mod_inverse(e, phi)

        return FullKeyPair(
            public=PublicKey(n=n, e=e),
            private=PrivateKey(n=n, d=d),
            p=p,
            q=q,
            phi=phi,
        )


def build_key_pair_from_primes(p: int, q: int, e: int) -> FullKeyPair:
    """Строит ключевую пару RSA по заданным p, q и e. Для демонстрации ручного примера."""
    if p == q:
        raise ValueError("p и q должны быть разными простыми числами.")

    if not is_probable_prime_fermat(p) or not is_probable_prime_fermat(q):
        raise ValueError("p и q должны быть простыми числами.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError("e должно быть взаимно просто с phi(n).")

    d = mod_inverse(e, phi)

    return FullKeyPair(
        public=PublicKey(n=n, e=e),
        private=PrivateKey(n=n, d=d),
        p=p,
        q=q,
        phi=phi,
    )


def text_to_blocks(text: str) -> list[int]:
    """
    Представляет текст как последовательность чисел.
    Каждый символ переводится в его Unicode-код с помощью ord().
    """
    return [ord(ch) for ch in text]


def blocks_to_text(blocks: list[int]) -> str:
    """Восстанавливает текст из последовательности числовых кодов символов."""
    try:
        return "".join(chr(block) for block in blocks)
    except ValueError as ex:
        raise ValueError("Расшифрованные блоки не удалось преобразовать в символы Unicode.") from ex


def encrypt_blocks(blocks: list[int], public_key: PublicKey) -> list[int]:
    """Шифрует числовые блоки RSA: c = m^e mod n."""
    encrypted = []

    for block in blocks:
        if block < 0:
            raise ValueError("Блок открытого текста не может быть отрицательным.")
    
        if block >= public_key.n:
            raise ValueError(
                f"Блок {block} не меньше модуля n={public_key.n}. "
                "Сгенерируйте ключи с большим модулем или разбейте данные иначе."
            )

        encrypted.append(mod_pow(block, public_key.e, public_key.n))

    return encrypted


def decrypt_blocks(blocks: list[int], private_key: PrivateKey) -> list[int]:
    """Расшифровывает числовые блоки RSA: m = c^d mod n."""
    return [mod_pow(block, private_key.d, private_key.n) for block in blocks]


def encrypt_text(text: str, public_key: PublicKey) -> list[int]:
    return encrypt_blocks(text_to_blocks(text), public_key)


def decrypt_to_text(cipher_blocks: list[int], private_key: PrivateKey) -> str:
    return blocks_to_text(decrypt_blocks(cipher_blocks, private_key))


def parse_ints(raw: str) -> list[int]:
    """Парсит последовательность целых чисел, разделенных пробелами, запятыми, точками с запятой или переводами строк."""
    cleaned = raw.replace("[", " ").replace("]", " ").replace(",", " ").replace(";", " ")
    parts = cleaned.split()

    if not parts:
        raise ValueError("Не найдено ни одного целого числа.")

    return [int(part) for part in parts]


def parse_key(raw: str, key_type: str) -> PublicKey | PrivateKey:
    """
    Парсит ключ из строки.
    Для открытого ключа: n e.
    Для закрытого ключа: n d.
    """
    values = parse_ints(raw)\

    if len(values) != 2:
        raise ValueError("Ключ должен состоять ровно из двух чисел.")

    if key_type == "public":
        return PublicKey(n=values[0], e=values[1])

    if key_type == "private":
        return PrivateKey(n=values[0], d=values[1])

    raise ValueError("Неизвестный тип ключа.")


def ciphertext_to_string(blocks: list[int]) -> str:
    """Готовит шифртекст для сохранения в файл."""
    return " ".join(str(block) for block in blocks)


def read_text_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def write_text_file(path: str, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")


def is_square(value: int) -> bool:
    if value < 0:
        return False

    root = math.isqrt(value)

    return root * root == value


def ceil_sqrt(value: int) -> int:
    root = math.isqrt(value)

    if root * root == value:
        return root

    return root + 1


def fermat_factorization(n: int, max_iterations: int = 1_000_000) -> tuple[int, int, int]:
    """
    Атака Ферма на факторизацию RSA-модуля.
    Эффективна, когда p и q близки друг к другу: n = p*q = a^2 - b^2 = (a-b)(a+b).
    Возвращает p, q и количество итераций.
    """
    if n <= 1:
        raise ValueError("Модуль n должен быть больше 1.")

    if n % 2 == 0:
        return 2, n // 2, 0

    a = ceil_sqrt(n)

    for iteration in range(max_iterations + 1):
        b_squared = a * a - n
    
        if is_square(b_squared):
            b = math.isqrt(b_squared)
            p = a - b
            q = a + b
        
            if p * q == n and p > 1 and q > 1:
                return min(p, q), max(p, q), iteration
    
        a += 1

    raise ValueError(
        "Не удалось разложить n методом Ферма за заданное число итераций. "
        "Вероятно, множители p и q недостаточно близки или n слишком велико для учебной атаки."
    )


def attack_fermat_recover_private_key(public_key: PublicKey, max_iterations: int = 1_000_000) -> tuple[PrivateKey, int, int, int, int]:
    """
    Восстанавливает закрытый ключ RSA через факторизацию n методом Ферма.
    Возвращает private_key, p, q, phi, iterations.
    """
    p, q, iterations = fermat_factorization(public_key.n, max_iterations=max_iterations)
    phi = (p - 1) * (q - 1)
    d = mod_inverse(public_key.e, phi)

    return PrivateKey(n=public_key.n, d=d), p, q, phi, iterations


def ask_public_key(current_key: PublicKey | None) -> PublicKey:
    if current_key is not None:
        print(f"\nТекущий открытый ключ: n={current_key.n}, e={current_key.e}")
        raw = input("Нажмите Enter, чтобы использовать его, или введите новый ключ в формате n e: ").strip()

        if raw == "":
            return current_key
    else:
        raw = input("\nВведите открытый ключ в формате n e: ").strip()

    parsed = parse_key(raw, "public")
    assert isinstance(parsed, PublicKey)

    return parsed


def ask_private_key(current_key: PrivateKey | None) -> PrivateKey:
    if current_key is not None:
        print(f"\nТекущий закрытый ключ: n={current_key.n}, d={current_key.d}")
        raw = input("Нажмите Enter, чтобы использовать его, или введите новый ключ в формате n d: ").strip()

        if raw == "":
            return current_key
    else:
        raw = input("\nВведите закрытый ключ в формате n d: ").strip()

    parsed = parse_key(raw, "private")
    assert isinstance(parsed, PrivateKey)

    return parsed


def show_key_pair(key_pair: FullKeyPair) -> None:
    print("\nСгенерирована ключевая пара RSA:")
    print(f"\tp = {key_pair.p}")
    print(f"\tq = {key_pair.q}")
    print(f"\tn = {key_pair.public.n}")
    print(f"\tphi(n) = {key_pair.phi}")
    print(f"\tОткрытый ключ (n, e): {key_pair.public.n} {key_pair.public.e}")
    print(f"\tЗакрытый ключ (n, d): {key_pair.private.n} {key_pair.private.d}")


def show_demo() -> None:
    """Демонстрация ручных параметров на слове WIZARD."""
    key_pair = build_key_pair_from_primes(DEMO_P, DEMO_Q, DEMO_E)
    encrypted = encrypt_text(DEMO_WORD, key_pair.public)
    decrypted = decrypt_to_text(encrypted, key_pair.private)

    print(f"\nДемонстрация RSA на слове {DEMO_WORD}")
    print("-" * 50)
    print(f"p = {key_pair.p}, q = {key_pair.q}")
    print(f"n = p*q = {key_pair.public.n}")
    print(f"phi(n) = (p-1)*(q-1) = {key_pair.phi}")
    print(f"e = {key_pair.public.e}")
    print(f"d = {key_pair.private.d}")
    print(f"Открытый текст: {DEMO_WORD}")
    print(f"Числовые блоки: {text_to_blocks(DEMO_WORD)}")
    print(f"Шифртекст: {encrypted}")
    print(f"Расшифрование: {decrypted}")

    recovered_private_key, p, q, phi, iterations = attack_fermat_recover_private_key(key_pair.public)
    attacked_text = decrypt_to_text(encrypted, recovered_private_key)
    print("\nДемонстрация атаки Ферма для малых параметров RSA")
    print(f"Найдено: p={p}, q={q}, phi(n)={phi}, d={recovered_private_key.d}, итераций={iterations}")
    print(f"Расшифрование шифртекста после атаки: {attacked_text}")
    print("-" * 50)


def show_big_numbers_demo() -> None:
    """Демонстрация RSA на слове WIZARD с автоматически сгенерированными большими числами."""
    key_pair = generate_key_pair(prime_bits=DEFAULT_PRIME_BITS)
    encrypted = encrypt_text(DEMO_WORD, key_pair.public)
    decrypted = decrypt_to_text(encrypted, key_pair.private)

    print("\nДемонстрация RSA на больших числах")
    print("-" * 50)
    print(f"Битовая длина p и q: {DEFAULT_PRIME_BITS}")
    print(f"p = {key_pair.p}")
    print(f"q = {key_pair.q}")
    print(f"n = {key_pair.public.n}")
    print(f"phi(n) = {key_pair.phi}")
    print(f"e = {key_pair.public.e}")
    print(f"d = {key_pair.private.d}")
    print(f"Открытый текст: {DEMO_WORD}")
    print(f"Числовые блоки: {text_to_blocks(DEMO_WORD)}")
    print(f"Шифртекст: {encrypted}")
    print(f"Расшифрование: {decrypted}")
    print("-" * 50)


def encrypt_file_flow(current_public_key: PublicKey | None) -> None:
    public_key = ask_public_key(current_public_key)
    input_path = input("Введите путь к файлу с открытым текстом: ").strip().strip('"')
    output_path = input("Введите путь для сохранения шифртекста или нажмите Enter для auto .enc.txt: ").strip().strip('"')

    if output_path == "":
        output_path = str(Path(input_path).with_suffix(".enc.txt"))

    plaintext = read_text_file(input_path)
    encrypted = encrypt_text(plaintext, public_key)
    write_text_file(output_path, ciphertext_to_string(encrypted))

    print(f"\nФайл зашифрован. Шифртекст сохранен: {output_path}")


def decrypt_file_flow(current_private_key: PrivateKey | None) -> None:
    private_key = ask_private_key(current_private_key)
    input_path = input("Введите путь к файлу с шифртекстом: ").strip().strip('"')
    output_path = input("Введите путь для сохранения открытого текста или нажмите Enter для auto .dec.txt: ").strip().strip('"')

    if output_path == "":
        output_path = str(Path(input_path).with_suffix(".dec.txt"))

    raw_ciphertext = read_text_file(input_path)
    cipher_blocks = parse_ints(raw_ciphertext)
    plaintext = decrypt_to_text(cipher_blocks, private_key)
    write_text_file(output_path, plaintext)

    print(f"\nФайл расшифрован. Открытый текст сохранен: {output_path}")


def encrypt_text_flow(current_public_key: PublicKey | None) -> None:
    public_key = ask_public_key(current_public_key)
    plaintext = input("Введите открытый текст: ")
    encrypted = encrypt_text(plaintext, public_key)

    print("\nРезультат шифрования:")
    print(ciphertext_to_string(encrypted))


def decrypt_text_flow(current_private_key: PrivateKey | None) -> None:
    private_key = ask_private_key(current_private_key)
    raw_ciphertext = input("Введите шифртекст в виде чисел через пробел: ")
    cipher_blocks = parse_ints(raw_ciphertext)
    plaintext = decrypt_to_text(cipher_blocks, private_key)

    print("\nРезультат расшифрования:")
    print(plaintext)


def attack_flow(current_public_key: PublicKey | None) -> None:
    public_key = ask_public_key(current_public_key)
    raw_iterations = input("Максимальное число итераций атаки Ферма или Enter для 1000000: ").strip()
    max_iterations = 1_000_000 if raw_iterations == "" else int(raw_iterations)

    recovered_private_key, p, q, phi, iterations = attack_fermat_recover_private_key(
        public_key,
        max_iterations=max_iterations,
    )

    print("\nАтака Ферма выполнена:")
    print(f"\tp = {p}")
    print(f"\tq = {q}")
    print(f"\tphi(n) = {phi}")
    print(f"\tВосстановленный закрытый ключ (n, d): {recovered_private_key.n} {recovered_private_key.d}")
    print(f"\tКоличество итераций: {iterations}")

    raw_ciphertext = input("Введите шифртекст для расшифрования восстановленным ключом или нажмите Enter, чтобы пропустить: ").strip()

    if raw_ciphertext != "":
        cipher_blocks = parse_ints(raw_ciphertext)
        plaintext = decrypt_to_text(cipher_blocks, recovered_private_key)
        print(f"\nОткрытый текст после атаки: {plaintext}")


def print_menu() -> None:
    print("\nВыберите действие:")
    print(f"\t1 - Показать демонстрацию на {DEMO_WORD}")
    print("\t2 - Сгенерировать ключевую пару RSA")
    print("\t3 - Зашифровать текст из файла")
    print("\t4 - Расшифровать шифртекст из файла")
    print("\t5 - Зашифровать введенную строку")
    print("\t6 - Расшифровать введенный шифртекст")
    print("\t7 - Запустить атаку Ферма на RSA")
    print("\t8 - Показать демонстрацию на больших числах")
    print("\t0 - Завершить программу")


def run_interactive() -> None:
    print("Практическая работа: криптосистема RSA")
    print(f"Параметры демо: p={DEMO_P}, q={DEMO_Q}, e={DEMO_E}, слово={DEMO_WORD}")
    print(f"Генерация больших ключей по умолчанию: p и q по {DEFAULT_PRIME_BITS} бит")

    current_key_pair: FullKeyPair | None = None

    while True:
        try:
            print_menu()
            action = input("Введите номер действия: ").strip()

            if action == "0":
                print("Завершение программы.")
                break

            if action == "1":
                show_demo()

            elif action == "2":
                raw_bits = input(f"Введите битовую длину p и q или Enter для {DEFAULT_PRIME_BITS}: ").strip()
                prime_bits = DEFAULT_PRIME_BITS if raw_bits == "" else int(raw_bits)
                current_key_pair = generate_key_pair(prime_bits=prime_bits)
                show_key_pair(current_key_pair)

            elif action == "3":
                encrypt_file_flow(current_key_pair.public if current_key_pair else None)

            elif action == "4":
                decrypt_file_flow(current_key_pair.private if current_key_pair else None)

            elif action == "5":
                encrypt_text_flow(current_key_pair.public if current_key_pair else None)

            elif action == "6":
                decrypt_text_flow(current_key_pair.private if current_key_pair else None)

            elif action == "7":
                attack_flow(current_key_pair.public if current_key_pair else None)

            elif action == "8":
                show_big_numbers_demo()

            else:
                print("Некорректный номер действия.")

        except Exception as ex:
            print(f"\nОшибка: {ex}")


if __name__ == "__main__":
    show_demo()
    run_interactive()
