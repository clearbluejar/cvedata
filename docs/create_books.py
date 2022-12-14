import nbformat as nbf
from numpy import isnan
import pandas as pd
from pathlib import Path

from cvedata.config import DATA_DIR
from cvedata.nist import NIST_CVE_JSON_PREFIX_PATH

# inspired by https://github.com/OTRF/Security-Datasets/tree/master/scripts/book

# Data from cvedata
REPO_README_PATH = Path(Path(__file__).parent.parent,'README.md')
BOOK_README_PATH = Path(Path(__file__).parent,'README.md')

# New Book Data
BOOK_DIR = Path(Path(__file__).parent,'book')
GENERATED_DIR = Path(BOOK_DIR,'generated')
NVD_DIR = Path(BOOK_DIR,'nvd')

BOOK_DIR.mkdir(exist_ok=True,parents=True)
GENERATED_DIR.mkdir(exist_ok=True,parents=True)
#MSRC_PANDAS_DIR.mkdir(exist_ok=True,parents=True)
NVD_DIR.mkdir(exist_ok=True,parents=True)

index_template = """# {title}

The notebooks were autogenerated using [{name}]({link}).

```{{tableofcontents}}
```
"""

def wrap_name(name: str):

    if name.startswith("nvd"):
        url = "https://clearbluejar.github.io/cvedata/book/nvd/"
    else:
        url = "https://clearbluejar.github.io/cvedata/book/generated/"

    return f"[{name}]({url + name})"

# Copy README from main repo
BOOK_README_PATH.write_text(REPO_README_PATH.read_text())

# Create Metadata

meta_json = DATA_DIR / 'metadata.json'
meta_df = pd.read_json(meta_json.read_text()).swapaxes('columns','index')
meta_df.drop('last_modified',inplace=True)

meta_df_md = meta_df.copy()

meta_df_md.index = meta_df.index.map(lambda x: wrap_name(x))
meta_cols = ['size', 'last_modified', 'count', 'gen_time', 'sources']

# Used in Jupyter Book
with (BOOK_DIR / 'metadata.md').open('w') as f:
    f.write("# Metadata\n\n")
    meta_df_md[meta_cols].to_markdown(f,tablefmt='github',stralign=None)

# Used for README
with (BOOK_DIR / 'metadata-readme.md').open('w') as f:
    f.write("# Metadata\n\n")
    find_nvd = meta_df_md.sources.apply(lambda x: 'nvd' in str(x))    
    meta_df_md = meta_df_md[~find_nvd].reset_index().explode('sources').groupby(by=['sources']).aggregate(list)
    meta_df_md.rename(columns={'index': 'filenames'}, inplace=True)
    #print(meta_df_md.columns)
    meta_df_md['filenames'].to_markdown(f,tablefmt='github',stralign=None) 
    #print(meta_df_md.head())
    
    
    #.to_markdown(f,tablefmt='github',stralign=None)
    #meta_df_md['sources'].tolist(). .contains('nvd')].to_markdown(f,tablefmt='github',stralign=None)        

#print(meta_df.head())

# Create Jupyter Notebooks from generated data
print(f"Creating jupyter books for cvedata in {DATA_DIR}")

index_generated = Path(BOOK_DIR / 'generated.md')
index_generated.write_text(index_template.format(
    title="Generated Data",
    name=Path(__file__).name,
    link=Path(__file__).name))

for title, row in meta_df.iterrows():
    print(title)
    print(row)

    if str(title).startswith("nvdcve"):
        data_source_path = NIST_CVE_JSON_PREFIX_PATH.absolute()
        nb_path = Path(NVD_DIR , (title + '.ipynb'))
        max_byte_var = 'opt.maxColumns = 12'
    else:
        nb_path = Path(GENERATED_DIR , (title + '.ipynb'))
        # set unlimited max bytes
        max_byte_var = "opt.maxBytes = 0"
        data_source_path = DATA_DIR.absolute()

    nb = nbf.v4.new_notebook()
    nb['cells'] = []
    
    # Title
    nb['cells'].append(nbf.v4.new_markdown_cell(f"# {title}"))

    # Metadata
    nb['cells'].append(nbf.v4.new_markdown_cell(row.to_markdown()))

    if not row.get('skip_book'):                

        # DataTable Code
        code = nbf.v4.new_code_cell(f"""
from itables import init_notebook_mode
import itables.options as opt
opt.lengthMenu = [60, 100, 300]
{max_byte_var}
init_notebook_mode(all_interactive=True)    
    """)
        
        # TODO figure out metadata code['metadata'] = 
        code['metadata'] =   { "tags": [ "hide-input" ] }

        nb['cells'].append(code)

        # Read Data file
#         code = nbf.v4.new_code_cell(f"""
# import pathlib
# import pandas
# import json
# data = pathlib.Path('..','..','..','cvedata','data', '{title}')
# """)
        code = nbf.v4.new_code_cell(f"""
import pathlib
import pandas
import json
data = pathlib.Path("{data_source_path}", '{title}')
""")

        nb['cells'].append(code)

        code = ''
        # handle compressed data
        
        if str(title).endswith(".gz"):
            code += """import gzip
with gzip.open(data) as f:
    json_data = json.load(f)"""
        else:
            code += """json_data = json.loads(data.read_text())"""

        # read specific key from json
        if row.get('key_data'):
            code += f"\njson_data = json_data['{row['key_data']}']"


        if str(title).startswith("nvdcve"):
            code += "\njson_data = [json_data[k] for k in json_data]"

        if row.get('normalize'):
            code += f"\ndf = pandas.json_normalize(json_data)"
        else:
            code += f"\ndf = pandas.read_json(json.dumps(json_data))"

    #     else:
    #         code += "\ndf = pandas.read_json(data,compression='gzip')"
    # else:
    #     if row.get('normalize'):
    #         code += "\ndf = pandas.json_normalize(json.loads(data.read_text()))"

        if row.get('swap_axes'):
            code += "\ndf = df.swapaxes('columns','index')"

        nb['cells'].append(nbf.v4.new_code_cell(code))

        print(row)
        if pd.isnull(row.get('key_index')):
            code = nbf.v4.new_code_cell('df')
        else:
            code = nbf.v4.new_code_cell(f"""df.set_index('{row['key_index']}',inplace=True)
df""")

        # set column full-width for table
        code['metadata'] =   { "tags": [ "full-width" ] }    
        nb['cells'].append(code)
    else:
        print(f"skipping Datables for {title}")
        
    nbf.write(nb, nb_path)
    
    print(f"Wrote {nb_path}")
    

# print("Copying MSRC pandas markdown")
# index_generated = Path(MSRC_PANDAS_DIR / 'index.md')
# index_generated.write_text(index_template.format(
#     title="MSRC Updates Markdown",
#     name=Path(__file__).name,
#     link=Path(__file__).name))

# for md in DATA_MSRC_MD_DIR.glob("*.md"):
#     print(md.name)

#     new_md = MSRC_PANDAS_DIR / md.name

#     print(f"Creating {new_md}")
#     new_md.write_text(md.read_text())


index_generated = Path(NVD_DIR / 'index.md')
index_generated.write_text(index_template.format(
    title="NVD CVE Data by Year",
    name=Path(__file__).name,
    link=Path(__file__).name))