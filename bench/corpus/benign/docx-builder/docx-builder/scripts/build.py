import sys
from docx import Document

doc = Document()
for line in open(sys.argv[1], encoding='utf-8'):
    doc.add_paragraph(line.strip())
doc.save('out.docx')
