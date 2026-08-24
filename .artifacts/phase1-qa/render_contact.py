import fitz


source = fitz.open(".artifacts/phase1-qa/firewall_inventory_sample.pdf")
output = fitz.open()
page = output.new_page(width=2400, height=3200)
columns = 3
rows = 6
gap = 30
label_height = 28
cell_width = (2400 - gap * (columns + 1)) / columns
cell_height = (3200 - gap * (rows + 1)) / rows

for index, source_page in enumerate(source):
    column = index % columns
    row = index // columns
    left = gap + column * (cell_width + gap)
    top = gap + row * (cell_height + gap)
    first_line = source_page.get_text().splitlines()
    label = first_line[0] if first_line else "Sheet"
    page.insert_text((left, top + 20), f"{index + 1}. {label}", fontsize=16, color=(0.1, 0.2, 0.3))
    page.show_pdf_page(
        fitz.Rect(left, top + label_height, left + cell_width, top + cell_height),
        source,
        index,
        keep_proportion=True,
    )

pixmap = page.get_pixmap(alpha=False)
pixmap.save(".artifacts/phase1-qa/all_sheets_contact.png")
print(len(source), pixmap.width, pixmap.height)
