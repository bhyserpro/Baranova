"""
Восстановление и подготовка БД уязвимостей ФСТЭК (Bank_uyazvimostey_IB.txt)
для импорта в Deductor Studio Academic.

Исходный файл был сохранён с потерей кодировки: каждая кириллическая буква
заменена символом U+FFFD («?»). Латиница, цифры, даты, CVSS-векторы,
идентификаторы CVE/CWE сохранились. Столбцы с небольшим набором значений
(класс, статус, наличие эксплойта, тип ПО и т.п.) восстанавливаются
по «маске» строки (длины слов совпадают с эталонным словарём БДУ ФСТЭК).

Результат: таблица с разделителем «табуляция», кодировка ANSI (cp1251),
первая строка — заголовок, без табуляций и переносов внутри ячеек
(аналог процедуры ПЕЧСИМВ/CLEAN из методички).

Запуск:  python3 build_vuln_txt.py <исходный.txt> <выходной.txt>
"""
import csv
import re
import sys

csv.field_size_limit(10**9)
Q = "�"


def mask(s: str) -> str:
    """Строка, где каждая потерянная буква — '?'"""
    return s.replace(Q, "?").strip()


def by_mask(word: str) -> str:
    return re.sub(r"[А-Яа-яЁё]", "?", word)


def make_dict(words):
    return {by_mask(w): w for w in words}


CLASS = make_dict(["Уязвимость кода", "Уязвимость архитектуры",
                   "Уязвимость многофакторная"])
STATUS = make_dict(["Подтверждена производителем", "Потенциальная уязвимость",
                    "Подтверждена в ходе исследований"])
EXPLOIT = make_dict(["Данные уточняются", "Существует в открытом доступе",
                     "Существует"])
FIX = make_dict(["Уязвимость устранена",
                 "Информация об устранении отсутствует"])
SOFT = make_dict([
    "Операционная система",
    "Прикладное ПО информационных систем",
    "Сетевое программное средство",
    "ПО сетевого программно-аппаратного средства",
    "Сетевое средство",
    "Микропрограммный код",
    "СУБД",
    "ПО виртуализации/ПО виртуального программно-аппаратного средства",
    "Программное средство защиты",
    "ПО программно-аппаратного средства АСУ ТП",
    "Программное средство АСУ ТП",
    "Средство АСУ ТП",
    "ПО программно-аппаратного средства",
    "ПО программно-аппаратных средств защиты",
    "Средство защиты",
    "Микропрограммный код аппаратных компонент компьютера",
])


def restore(value, table, default="Не указано"):
    m = mask(value)
    if not m:
        return default
    return table.get(m, default)


def soft_types(value):
    toks = [t for t in mask(value).split(", ") if t]
    res = [SOFT.get(t, "Прочее") for t in toks]
    return res or ["Не указано"]


def latin(value: str) -> str:
    """Оставить читаемую латинскую часть строки (имена продуктов, ОС)."""
    s = re.sub(r"(?<=[A-Za-z0-9])�(?=[A-Za-z0-9])", "-", value)
    words = [w for w in re.split(r"\s+", s) if w and Q not in w]
    s = " ".join(words)
    s = re.sub(r"\(\s*\)|\(\.\)", "", s)
    s = re.sub(r"\s+([,)])", r"\1", s).strip(" ,;:-")
    return s or "Не указано"


def vendors(value: str) -> str:
    """Вендоры через запятую; кириллические названия восстанавливаются
    по маске, где это однозначно, иначе помечаются как утраченные."""
    res = []
    for t in value.split(","):
        t = t.strip()
        if not t:
            continue
        if Q not in t:
            res.append(t)
        elif mask(t) == by_mask("Сообщество свободного программного обеспечения"):
            res.append("Сообщество свободного ПО")
        else:
            lat = latin(t)
            res.append(lat if lat != "Не указано" and len(lat) > 3
                       else "Российский вендор (название утрачено)")
    return ", ".join(dict.fromkeys(res)) or "Не указано"


def score(text, ver):
    m = re.search(r"CVSS " + re.escape(ver) + r"\D*?(\d+(?:,\d)?)", text)
    return float(m.group(1).replace(",", ".")) if m else None


def level2(s):
    if s is None:
        return "Не указано"
    if s == 10:
        return "Критический"
    if s >= 7:
        return "Высокий"
    if s >= 4:
        return "Средний"
    if s > 0:
        return "Низкий"
    return "Нет опасности"


def level3(s):
    if s is None:
        return "Не указано"
    if s >= 9:
        return "Критический"
    if s >= 7:
        return "Высокий"
    if s >= 4:
        return "Средний"
    if s > 0:
        return "Низкий"
    return "Нет опасности"


def vec(v, key):
    m = re.search(r"(?:^|/)" + key + r":([A-Z])", v)
    return m.group(1) if m else ""


AV = {"N": "Сетевой", "A": "Смежная сеть", "L": "Локальный", "P": "Физический"}


def first(pattern, s, default="Нет"):
    m = re.search(pattern, s)
    return m.group(0) if m else default


def clean(s):
    return re.sub(r"[\t\r\n]+", " ", str(s)).strip()


HEADER = [
    "Идентификатор", "Год выявления", "Дата выявления", "Вендор ПО",
    "Название ПО", "Тип ПО", "Тип ПО (основной)", "Класс уязвимости",
    "CVSS 2.0", "Оценка CVSS 2.0", "Уровень опасности CVSS 2.0",
    "CVSS 3.0", "Оценка CVSS 3.0", "Уровень опасности CVSS 3.0",
    "Вектор доступа", "Нарушение конфиденциальности", "Нарушение целостности",
    "Нарушение доступности", "Статус уязвимости", "Наличие эксплойта",
    "Информация об устранении", "CVE", "Тип ошибки CWE",
]


def main(src, dst):
    rows = list(csv.reader(open(src, encoding="utf-8", newline=""),
                           delimiter="\t"))
    out = [HEADER]
    for r in rows[1:]:
        if len(r) < 22 or not r[0].startswith("BDU"):
            continue
        s2, s3 = score(r[12], "2.0"), score(r[12], "3.0")
        v2, v3 = r[10].strip(), r[11].strip()
        v = v3 or v2
        cia = []
        for k in "CIA":
            x = vec(v, k)
            cia.append("1" if x in ("P", "C", "L", "H") else
                       ("0" if x == "N" else "?"))
        av = AV.get(vec(v, "AV"), "Не указано")
        types = soft_types(r[6])
        date = r[9].strip()
        year = date[-4:] if re.fullmatch(r"\d\d\.\d\d\.\d{4}", date) else "?"
        vendor = vendors(r[3])
        out.append([
            r[0].strip(), year, date if year != "?" else "?", vendor,
            latin(r[4]), "; ".join(dict.fromkeys(types)), types[0],
            restore(r[8], CLASS), v2 or "?",
            "%.1f" % s2 if s2 is not None else "?",
            level2(s2), v3 or "?",
            "%.1f" % s3 if s3 is not None else "?",
            level3(s3), av, *cia,
            restore(r[14], STATUS), restore(r[15], EXPLOIT),
            restore(r[16], FIX), first(r"CVE-\d{4}-\d+", r[18]),
            first(r"CWE-\d+|NVD-CWE-\w+", r[21], "Не указано"),
        ])
    with open(dst, "w", encoding="cp1251", errors="replace",
              newline="") as f:
        for row in out:
            f.write("\t".join(clean(c) for c in row) + "\r\n")
    print(f"записано строк: {len(out) - 1}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
