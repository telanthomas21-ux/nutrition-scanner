import sqlite3
import pandas as pd

DB_PATH = "nutrition.db"
EXCEL_PATH = "Anuvaad_INDB_2024.11.xlsx"

def main():
    df = pd.read_excel(EXCEL_PATH, sheet_name="Sheet1")

    # Keep only useful columns
    cols = ["food_code", "food_name", "energy_kcal",
            "freesugar_g", "fat_g", "protein_g", "sodium_mg"]
    df = df[cols].dropna(subset=["food_code", "food_name"])

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for _, row in df.iterrows():
        pid = str(row["food_code"]).strip()
        name = str(row["food_name"]).strip()
        calories = float(row["energy_kcal"] or 0)
        sugar = float(row["freesugar_g"] or 0)
        fat = float(row["fat_g"] or 0)
        protein = float(row["protein_g"] or 0)
        sodium = float(row["sodium_mg"] or 0)

        # simple health flag (you can refine using your model)
        is_healthy = 1
        if sugar > 25 or fat > 20 or sodium > 400 or calories > 300:
            is_healthy = 0

        cur.execute("""
            INSERT OR IGNORE INTO products
            (id, name, calories, sugar, fat, protein, sodium, chemicals, is_healthy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (pid, name, calories, sugar, fat, protein, sodium, "", is_healthy))

    conn.commit()
    conn.close()
    print("Done importing INDB data")

if __name__ == "__main__":
    main()
