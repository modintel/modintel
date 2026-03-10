import fitz
doc = fitz.open('../docs/SRS.pdf')
with open('../docs/SRS.txt', 'w', encoding='utf-8') as f:
    for page in doc: f.write(page.get_text())
doc = fitz.open('../docs/SDS.pdf')
with open('../docs/SDS.txt', 'w', encoding='utf-8') as f:
    for page in doc: f.write(page.get_text())
