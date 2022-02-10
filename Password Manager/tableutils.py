PADDING = 8


def get_table_template(fields):
    out = ""
    for field in fields:
        out += "{:<" + str(len(field) + PADDING) + "}"
    return out


def get_headings(fields):
    headings = get_table_template(fields).format(*fields)
    border = ""
    for i in range(len(headings)):
        border += "="

    return border + "\n" + headings + "\n" + border


def get_entries(fields, entries):
    if len(fields) != len(entries[0]): return

    borderLength = len(get_table_template(fields).format(*fields))
    border = ""
    for i in range(borderLength):
        border += "="

    out = ""
    for entry in entries:
        out += get_table_template(fields).format(*entry) + "\n"

    return out + border
