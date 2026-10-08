"""Parse and total invoices."""

def total(items):
    return sum(i["qty"] * i["price"] for i in items)

def parse_line(line):
    name, qty, price = line.split(",")
    return {"name": name, "qty": int(qty), "price": float(price)}
