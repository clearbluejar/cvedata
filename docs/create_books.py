import nbformat as nbf
from numpy import isnan
import pandas as pd
from pathlib import Path

# inspired by https://github.com/OTRF/Security-Datasets/tree/master/scripts/book

# Data from cvedata
DATA_DIR = Path(Path(__file__).parent.parent,'cvedata','data')
DATA_MSRC_MD_DIR = Path(DATA_DIR, 'pandas')

# New Book Data
BOOK_DIR = Path(Path(__file__).parent,'book')
GENERATED_DIR = Path(BOOK_DIR,'generated')
MSRC_PANDAS_DIR = Path(BOOK_DIR,'msrc_pandas')

BOOK_DIR.mkdir(exist_ok=True,parents=True)
GENERATED_DIR.mkdir(exist_ok=True,parents=True)
MSRC_PANDAS_DIR.mkdir(exist_ok=True,parents=True)


index_template = """# {title}

The notebooks were autogenerated using [{name}]({link}).

```{{tableofcontents}}
```
"""

meta_json = DATA_DIR / 'metadata.json'
meta_df = pd.read_json(meta_json.read_text()).swapaxes('columns','index')
meta_df.drop('last_modified',inplace=True)

with (BOOK_DIR / 'metadata.md').open('w') as f:
    f.write("# Generated Metadata\n\n")
    meta_df.to_markdown(f)

print(meta_df.head())

print(f"Creating jupyter books for cvedata in {DATA_DIR}")

# index_generated = Path(GENERATED_DIR / 'index.md')
# index_generated.write_text(index_template.format(
#     title="Generated Data",
#     name=Path(__file__).name,
#     link=Path(__file__).name))

for title, row in meta_df.iterrows():
    print(title)
    print(row)

    nb_path = Path(GENERATED_DIR , (title + '.ipynb'))

    nb = nbf.v4.new_notebook()
    nb['cells'] = []
    
    # Title
    nb['cells'].append(nbf.v4.new_markdown_cell(f"# {title}"))

    # Metadata
    nb['cells'].append(nbf.v4.new_markdown_cell(row.to_markdown()))

    if not row.get('skip_book'):                

        # DataTable Code
        code = nbf.v4.new_code_cell("""
from itables import init_notebook_mode
import itables.options as opt
opt.lengthMenu = [60, 100, 300]
opt.maxBytes = 0
init_notebook_mode(all_interactive=True)    
    """.format(size=row['size']))
        
        # TODO figure out metadata code['metadata'] = 
        code['metadata'] =   { "tags": [ "hide-input" ] }

        nb['cells'].append(code)

        # Read Data file
        code = nbf.v4.new_code_cell("""
import pathlib
import pandas
import json
data = pathlib.Path('..','..','..','cvedata','data', '{title}')
    """.format(title=title))

        nb['cells'].append(code)

        code = ''
        # handle compressed data
        if str(title).endswith(".gz"):
            if row.get('normalize'):
                code += """import gzip
gz_data = None
with gzip.open(data) as f:
    gz_data = json.load(f)

df = pandas.json_normalize(gz_data)"""
            else:
                code += "\ndf = pandas.read_json(data,compression='gzip')"
        else:
            if row.get('normalize'):
                code += "\ndf = pandas.json_normalize(json.loads(data.read_text()))"
            else:
                code += "\ndf = pandas.read_json(data)"

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
    

print("Copying MSRC pandas markdown")
index_generated = Path(MSRC_PANDAS_DIR / 'index.md')
index_generated.write_text(index_template.format(
    title="MSRC Updates Markdown",
    name=Path(__file__).name,
    link=Path(__file__).name))

for md in DATA_MSRC_MD_DIR.glob("*.md"):
    print(md.name)

    new_md = MSRC_PANDAS_DIR / md.name

    print(f"Creating {new_md}")
    new_md.write_text(md.read_text())