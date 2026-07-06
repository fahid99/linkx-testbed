"""Create and seed the database. Usage: python -m scripts.init_db"""
from app.seed import seed_all

if __name__ == "__main__":
    seed_all()
