from pathlib import Path

from cvedata import __version__

DATA_DIR = Path(__file__).parent / 'data'
PANDAS_DIR = Path(DATA_DIR, 'pandas')
METADATA_PATH = Path(DATA_DIR, 'metadata.json')
CACHE_PATH = Path(DATA_DIR, '.cache')

DATA_DIR.mkdir(exist_ok=True,parents=True)
CACHE_PATH.mkdir(exist_ok=True,parents=True)

REPO_REL_VERSION_INFO = f"https://api.github.com/repos/clearbluejar/cvedata/releases/tags/v{__version__}"
REPO_REL_DOWNLOAD_URL = f"https://github.com/clearbluejar/cvedata/releases/download/v{__version__}/"

