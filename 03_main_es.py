
"""
Практическая работа: электронная подпись ГОСТ Р 34.10-2012 (Python)

Реализованы:
1) арифметика точек эллиптической кривой над конечным простым полем;
2) генерация ключевой пары для схемы подписи ГОСТ Р 34.10-2012;
3) формирование электронной подписи для выбранного файла;
4) проверка электронной подписи по файлу, файлу подписи и открытому ключу.

Готовые криптографические библиотеки для реализации подписи не используются.
Допускаемая по заданию готовая реализация ГОСТ Р 34.11-2012 используется только
для вычисления хэша сообщения: пакет gostcrypto, модуль gosthash.

Перед запуском установите зависимость для хэш-функции:
    pip install gostcrypto
"""


import secrets
from dataclasses import dataclass
from gostcrypto import gosthash
from pathlib import Path


DEFAULT_CURVE_NAME = "id-GostR3410-2001-CryptoPro-A-ParamSet"
DEMO_TEXT = "Test message for GOST R 34.10-2012 digital signature."

# Фиксированный демонстрационный ключ используется только для повторяемости примера.
# При обычной работе ключевая пара генерируется случайно.
DEMO_FIXED_PRIVATE_KEY = 123456789


@dataclass(frozen=True)
class Point:
    x: int | None = None
    y: int | None = None

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


@dataclass(frozen=True)
class EllipticCurve:
    name: str
    p: int
    a: int
    b: int
    q: int
    base_point: Point


@dataclass(frozen=True)
class PrivateKey:
    d: int


@dataclass(frozen=True)
class PublicKey:
    q_point: Point


@dataclass(frozen=True)
class FullKeyPair:
    private: PrivateKey
    public: PublicKey


@dataclass(frozen=True)
class Signature:
    r: int
    s: int


INFINITY = Point()

# Параметры эллиптической кривой из набора CryptoPro-A для 256-битной схемы.
# Формат: y^2 = x^3 + a*x + b (mod p), базовая точка P имеет порядок q.
GOST_CURVE = EllipticCurve(
    name=DEFAULT_CURVE_NAME,
    p=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16),
    a=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", 16),
    b=0xA6,
    q=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16),
    base_point=Point(
        x=0x1,
        y=int("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14", 16),
    ),
)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Расширенный алгоритм Евклида.
    Возвращает gcd(a, b), x, y такие, что a*x + b*y = gcd(a, b).
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Возвращает обратный элемент a^(-1) по модулю m."""
    g, x, _ = extended_gcd(a % m, m)

    if g != 1:
        raise ValueError(f"Число {a} не имеет обратного элемента по модулю {m}, так как gcd != 1.")

    return x % m


def is_point_on_curve(point: Point, curve: EllipticCurve = GOST_CURVE) -> bool:
    if point.is_infinity:
        return True

    assert point.x is not None and point.y is not None

    left = (point.y * point.y) % curve.p
    right = (point.x * point.x * point.x + curve.a * point.x + curve.b) % curve.p

    return left == right


def validate_curve_parameters(curve: EllipticCurve = GOST_CURVE) -> None:
    if curve.p <= 3:
        raise ValueError("Модуль p должен быть простым числом больше 3.")

    discriminant = (-4 * curve.a * curve.a * curve.a - 27 * curve.b * curve.b) % curve.p

    if discriminant == 0:
        raise ValueError("Параметры a и b задают вырожденную эллиптическую кривую.")

    if not is_point_on_curve(curve.base_point, curve):
        raise ValueError("Базовая точка не принадлежит выбранной эллиптической кривой.")


def point_add(first: Point, second: Point, curve: EllipticCurve = GOST_CURVE) -> Point:
    """Складывает две точки эллиптической кривой."""
    if first.is_infinity:
        return second

    if second.is_infinity:
        return first

    if not is_point_on_curve(first, curve) or not is_point_on_curve(second, curve):
        raise ValueError("Одна из точек не принадлежит выбранной эллиптической кривой.")

    assert first.x is not None and first.y is not None
    assert second.x is not None and second.y is not None

    if first.x == second.x and (first.y + second.y) % curve.p == 0:
        return INFINITY

    if first == second:
        numerator = (3 * first.x * first.x + curve.a) % curve.p
        denominator = (2 * first.y) % curve.p
    else:
        numerator = (second.y - first.y) % curve.p
        denominator = (second.x - first.x) % curve.p

    if denominator == 0:
        return INFINITY

    lambda_value = (numerator * mod_inverse(denominator, curve.p)) % curve.p
    x3 = (lambda_value * lambda_value - first.x - second.x) % curve.p
    y3 = (lambda_value * (first.x - x3) - first.y) % curve.p
    result = Point(x3, y3)

    if not is_point_on_curve(result, curve):
        raise ValueError("Ошибка сложения точек: результат не принадлежит кривой.")

    return result


def scalar_multiply(k: int, point: Point, curve: EllipticCurve = GOST_CURVE) -> Point:
    """Вычисляет k*P методом удвоения и сложения."""
    if k < 0:
        raise ValueError("Множитель k должен быть неотрицательным.")

    if not is_point_on_curve(point, curve):
        raise ValueError("Точка не принадлежит выбранной эллиптической кривой.")

    result = INFINITY
    addend = point

    while k > 0:
        if k % 2 == 1:
            result = point_add(result, addend, curve)

        addend = point_add(addend, addend, curve)
        k //= 2

    return result


def hash_bytes_gost3411_2012(data: bytes) -> bytes:
    """
    Вычисляет хэш ГОСТ Р 34.11-2012 длиной 256 бит.
    Используется готовая реализация хэш-функции, что допускается заданием.
    """
    hash_object = gosthash.new("streebog256")
    hash_object.update(data)

    return hash_object.digest()


def hash_to_int(data: bytes, curve: EllipticCurve = GOST_CURVE) -> int:
    digest = hash_bytes_gost3411_2012(data)
    value = int.from_bytes(digest, byteorder="big") % curve.q

    if value == 0:
        return 1

    return value


def read_binary_file(path: str) -> bytes:
    file_path = Path(path)

    if not file_path.exists() or not file_path.is_file():
        raise ValueError(f"Файл не найден: {path}")

    data = file_path.read_bytes()

    if len(data) == 0:
        raise ValueError("Файл не должен быть пустым.")

    return data


def write_text_file(path: str, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")


def read_text_file(path: str) -> str:
    file_path = Path(path)

    if not file_path.exists() or not file_path.is_file():
        raise ValueError(f"Файл не найден: {path}")

    return file_path.read_text(encoding="utf-8")


def generate_gost_key_pair(curve: EllipticCurve = GOST_CURVE) -> FullKeyPair:
    """Генерирует закрытый ключ d и открытый ключ Q = d*P."""
    validate_curve_parameters(curve)
    private_value = secrets.randbelow(curve.q - 1) + 1
    public_point = scalar_multiply(private_value, curve.base_point, curve)

    return FullKeyPair(
        private=PrivateKey(d=private_value),
        public=PublicKey(q_point=public_point),
    )


def build_key_pair_from_private(private_key: PrivateKey, curve: EllipticCurve = GOST_CURVE) -> FullKeyPair:
    validate_private_key(private_key, curve)
    public_point = scalar_multiply(private_key.d, curve.base_point, curve)

    return FullKeyPair(private=private_key, public=PublicKey(q_point=public_point))


def validate_private_key(private_key: PrivateKey, curve: EllipticCurve = GOST_CURVE) -> None:
    if not 1 <= private_key.d < curve.q:
        raise ValueError(f"Закрытый ключ d должен удовлетворять условию 1 <= d < q, где q={curve.q}.")


def validate_public_key(public_key: PublicKey, curve: EllipticCurve = GOST_CURVE) -> None:
    if public_key.q_point.is_infinity:
        raise ValueError("Открытый ключ не может быть бесконечно удаленной точкой.")

    if not is_point_on_curve(public_key.q_point, curve):
        raise ValueError("Открытый ключ не принадлежит выбранной эллиптической кривой.")


def validate_signature(signature: Signature, curve: EllipticCurve = GOST_CURVE) -> None:
    if not 0 < signature.r < curve.q:
        raise ValueError("Компонента подписи r должна удовлетворять условию 0 < r < q.")

    if not 0 < signature.s < curve.q:
        raise ValueError("Компонента подписи s должна удовлетворять условию 0 < s < q.")


def sign_data(data: bytes, private_key: PrivateKey, curve: EllipticCurve = GOST_CURVE) -> Signature:
    """Формирует электронную подпись ГОСТ Р 34.10-2012 для массива байтов."""
    validate_private_key(private_key, curve)
    e = hash_to_int(data, curve)

    while True:
        k = secrets.randbelow(curve.q - 1) + 1
        c_point = scalar_multiply(k, curve.base_point, curve)

        if c_point.is_infinity:
            continue

        assert c_point.x is not None
    
        r = c_point.x % curve.q

        if r == 0:
            continue

        s = (r * private_key.d + k * e) % curve.q

        if s == 0:
            continue

        return Signature(r=r, s=s)


def verify_signature(
    data: bytes,
    signature: Signature,
    public_key: PublicKey,
    curve: EllipticCurve = GOST_CURVE,
) -> bool:
    """Проверяет электронную подпись ГОСТ Р 34.10-2012."""
    validate_public_key(public_key, curve)
    validate_signature(signature, curve)

    e = hash_to_int(data, curve)
    v = mod_inverse(e, curve.q)
    z1 = (signature.s * v) % curve.q
    z2 = (-signature.r * v) % curve.q
    first = scalar_multiply(z1, curve.base_point, curve)
    second = scalar_multiply(z2, public_key.q_point, curve)
    c_point = point_add(first, second, curve)

    if c_point.is_infinity:
        return False

    assert c_point.x is not None

    r_calculated = c_point.x % curve.q

    return r_calculated == signature.r


def parse_ints(raw: str) -> list[int]:
    cleaned = raw.replace("[", " ").replace("]", " ").replace(",", " ").replace(";", " ")
    parts = cleaned.split()

    if not parts:
        raise ValueError("Не найдено ни одного целого числа.")

    return [int(part) for part in parts]


def parse_named_int(raw: str, name: str) -> int | None:
    prefix = f"{name}="

    for line in raw.splitlines():
        stripped = line.strip()

        if stripped.startswith(prefix):
            return int(stripped[len(prefix):].strip())

    return None


def parse_private_key(raw: str) -> PrivateKey:
    named_d = parse_named_int(raw, "d")

    if named_d is not None:
        return PrivateKey(d=named_d)

    values = parse_ints(raw)

    if len(values) != 1:
        raise ValueError("Закрытый ключ должен содержать одно число d.")

    return PrivateKey(d=values[0])


def parse_public_key(raw: str) -> PublicKey:
    named_x = parse_named_int(raw, "x")
    named_y = parse_named_int(raw, "y")

    if named_x is not None and named_y is not None:
        return PublicKey(q_point=Point(named_x, named_y))

    values = parse_ints(raw)

    if len(values) != 2:
        raise ValueError("Открытый ключ должен содержать два числа: x y.")

    return PublicKey(q_point=Point(values[0], values[1]))


def parse_signature(raw: str) -> Signature:
    named_r = parse_named_int(raw, "r")
    named_s = parse_named_int(raw, "s")

    if named_r is not None and named_s is not None:
        return Signature(r=named_r, s=named_s)

    values = parse_ints(raw)

    if len(values) != 2:
        raise ValueError("Подпись должна содержать два числа: r s.")

    return Signature(r=values[0], s=values[1])


def signature_to_string(signature: Signature) -> str:
    return "\n".join([
        "GOST_SIGNATURE",
        f"curve={GOST_CURVE.name}",
        f"r={signature.r}",
        f"s={signature.s}",
        "",
    ])


def private_key_to_string(private_key: PrivateKey) -> str:
    return "\n".join([
        "GOST_PRIVATE_KEY",
        f"curve={GOST_CURVE.name}",
        f"d={private_key.d}",
        "",
    ])


def public_key_to_string(public_key: PublicKey) -> str:
    point = public_key.q_point

    assert point.x is not None and point.y is not None

    return "\n".join([
        "GOST_PUBLIC_KEY",
        f"curve={GOST_CURVE.name}",
        f"x={point.x}",
        f"y={point.y}",
        "",
    ])


def signature_default_path(input_path: str) -> str:
    source = Path(input_path)

    if source.suffix:
        return str(source.with_suffix(source.suffix + ".sig.txt"))

    return str(source.with_suffix(".sig.txt"))


def ask_existing_or_raw(prompt: str) -> str:
    raw = input(prompt).strip().strip('"')

    if raw == "":
        raise ValueError("Значение не должно быть пустым.")

    path = Path(raw)

    if path.exists() and path.is_file():
        return read_text_file(raw)

    return raw


def ask_private_key(current_private_key: PrivateKey | None) -> PrivateKey:
    if current_private_key is not None:
        print(f"\nТекущий закрытый ключ d={current_private_key.d}")
        raw = input("Нажмите Enter, чтобы использовать его, или введите d / путь к файлу ключа: ").strip().strip('"')

        if raw == "":
            return current_private_key

        if Path(raw).exists() and Path(raw).is_file():
            raw = read_text_file(raw)
    else:
        raw = ask_existing_or_raw("\nВведите закрытый ключ d или путь к файлу закрытого ключа: ")

    private_key = parse_private_key(raw)
    validate_private_key(private_key)

    return private_key


def ask_public_key(current_public_key: PublicKey | None) -> PublicKey:
    if current_public_key is not None:
        point = current_public_key.q_point

        assert point.x is not None and point.y is not None

        print(f"\nТекущий открытый ключ: x={point.x}, y={point.y}")
        raw = input("Нажмите Enter, чтобы использовать его, или введите x y / путь к файлу ключа: ").strip().strip('"')

        if raw == "":
            return current_public_key

        if Path(raw).exists() and Path(raw).is_file():
            raw = read_text_file(raw)
    else:
        raw = ask_existing_or_raw("\nВведите открытый ключ x y или путь к файлу открытого ключа: ")

    public_key = parse_public_key(raw)
    validate_public_key(public_key)

    return public_key


def show_key_pair(key_pair: FullKeyPair) -> None:
    public_point = key_pair.public.q_point

    assert public_point.x is not None and public_point.y is not None

    print("\nКлючевая пара ГОСТ Р 34.10-2012:")
    print(f"\tПараметры кривой: {GOST_CURVE.name}")
    print(f"\tЗакрытый ключ d: {key_pair.private.d}")
    print(f"\tОткрытый ключ Q = dP:")
    print(f"\t\tx = {public_point.x}")
    print(f"\t\ty = {public_point.y}")


def save_keys_flow(key_pair: FullKeyPair) -> None:
    private_path = input("Путь для сохранения закрытого ключа или Enter для private_key.txt: ").strip().strip('"')
    public_path = input("Путь для сохранения открытого ключа или Enter для public_key.txt: ").strip().strip('"')

    if private_path == "":
        private_path = "private_key.txt"

    if public_path == "":
        public_path = "public_key.txt"

    write_text_file(private_path, private_key_to_string(key_pair.private))
    write_text_file(public_path, public_key_to_string(key_pair.public))

    print(f"\nЗакрытый ключ сохранен: {private_path}")
    print(f"Открытый ключ сохранен: {public_path}")


def sign_file_flow(current_private_key: PrivateKey | None) -> None:
    private_key = ask_private_key(current_private_key)
    input_path = input("Введите путь к файлу, который нужно подписать: ").strip().strip('"')
    output_path = input("Введите путь для сохранения подписи или нажмите Enter для auto .sig.txt: ").strip().strip('"')

    if output_path == "":
        output_path = signature_default_path(input_path)

    data = read_binary_file(input_path)
    signature = sign_data(data, private_key)
    write_text_file(output_path, signature_to_string(signature))

    print("\nПодпись сформирована.")
    print(f"\tФайл: {input_path}")
    print(f"\tФайл подписи: {output_path}")
    print(f"\tr = {signature.r}")
    print(f"\ts = {signature.s}")


def verify_file_flow(current_public_key: PublicKey | None) -> None:
    public_key = ask_public_key(current_public_key)
    input_path = input("Введите путь к проверяемому файлу: ").strip().strip('"')
    signature_path = input("Введите путь к файлу электронной подписи: ").strip().strip('"')

    data = read_binary_file(input_path)
    signature = parse_signature(read_text_file(signature_path))
    is_valid = verify_signature(data, signature, public_key)

    print("\nРезультат проверки подписи:")
    print(f"\tФайл: {input_path}")
    print(f"\tФайл подписи: {signature_path}")

    if is_valid:
        print("\tПодпись корректна.")
    else:
        print("\tПодпись некорректна.")


def show_demo() -> None:
    """Демонстрирует формирование и проверку подписи на тестовом файле."""
    demo_path = Path("demo_message.txt")
    signature_path = Path("demo_message.sig.txt")
    demo_path.write_text(DEMO_TEXT, encoding="utf-8")

    private_key = PrivateKey(DEMO_FIXED_PRIVATE_KEY)
    key_pair = build_key_pair_from_private(private_key)
    signature = sign_data(read_binary_file(str(demo_path)), private_key)
    write_text_file(str(signature_path), signature_to_string(signature))
    verified = verify_signature(read_binary_file(str(demo_path)), signature, key_pair.public)

    print(f"\nДемонстрация ГОСТ Р 34.10-2012 на файле {demo_path}")
    print("-" * 50)
    show_key_pair(key_pair)
    print(f"\nТекст в файле: {DEMO_TEXT}")
    print(f"Файл подписи: {signature_path}")
    print(f"r = {signature.r}")
    print(f"s = {signature.s}")
    print(f"Результат проверки: {'подпись корректна' if verified else 'подпись некорректна'}")
    print("-" * 50)


def print_menu() -> None:
    print("\nВыберите действие:")
    print("\t1 - Показать демонстрацию на файле с текстом demo_message.txt")
    print("\t2 - Сгенерировать ключевую пару ГОСТ Р 34.10-2012")
    print("\t3 - Сформировать подпись для файла")
    print("\t4 - Проверить подпись файла")
    print("\t5 - Показать текущую ключевую пару")
    print("\t0 - Завершить программу")


def run_interactive() -> None:
    print("Практическая работа: электронная подпись ГОСТ Р 34.10-2012")
    print(f"Параметры эллиптической кривой: {GOST_CURVE.name}")

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
                current_key_pair = generate_gost_key_pair()
                show_key_pair(current_key_pair)
                save_answer = input("Сохранить ключи в файлы? (y/n): ").strip().lower()

                if save_answer == "y":
                    save_keys_flow(current_key_pair)

            elif action == "3":
                sign_file_flow(current_key_pair.private if current_key_pair else None)

            elif action == "4":
                verify_file_flow(current_key_pair.public if current_key_pair else None)

            elif action == "5":
                if current_key_pair is None:
                    print("\nКлючевая пара еще не сгенерирована в текущем сеансе.")
                else:
                    show_key_pair(current_key_pair)

            else:
                print("Некорректный номер действия.")

        except Exception as ex:
            print(f"\nОшибка: {ex}")


if __name__ == "__main__":
    run_interactive()
