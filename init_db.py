import sqlite3

# schema.sql 파일을 읽어서 pulse.db 생성
with open('schema.sql', 'r', encoding='utf-8') as f:
    sql_script = f.read()

conn = sqlite3.connect('pulse.db')
conn.executescript(sql_script)
conn.close()

print("✅ pulse.db 데이터베이스 생성 완료!")