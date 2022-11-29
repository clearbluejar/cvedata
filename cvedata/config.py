from pathlib import Path

DATA_DIR = Path(__file__).parent / 'data'
PANDAS_DIR = Path(DATA_DIR, 'pandas')
METADATA_PATH = Path(DATA_DIR, 'metadata.json')
CACHE_PATH = Path(DATA_DIR, '.cache')

DATA_DIR.mkdir(exist_ok=True,parents=True)
CACHE_PATH.mkdir(exist_ok=True,parents=True)