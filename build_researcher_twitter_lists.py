import tweepy
import os
import pandas as pd
from pandas import json_normalize
import json
from pathlib import Path
import time

from cvedata.acknowledgements import get_researcher_twitter_map_json

import auth_tweepy

auth = tweepy.OAuthHandler(os.getenv("consumer_key"),
                           os.getenv("consumer_secret"))
auth.set_access_token(os.getenv("access_token"),
                      os.getenv("access_token_secret"))


api = tweepy.API(auth, wait_on_rate_limit=True)
client = tweepy.Client(
    bearer_token=os.getenv("bearer_token"),
    consumer_key=os.getenv("consumer_key"),
    consumer_secret=os.getenv("consumer_secret"),
    access_token=os.getenv("access_token"),
    access_token_secret=os.getenv("access_token_secret"),
    wait_on_rate_limit=True,
)

# Used to create list
# list_name = "researchers with a CVE"
# list_description = "A list of researchers that have earned at least 1 CVE"

# twitter_list = api.create_list(name=list_name, description=list_description, mode='private')
# list_id = twitter_list._json["id"]

list_id = 1582329731005005825

researchers_json = get_researcher_twitter_map_json()
screen_name_to_researcher_map = {
    str(v[0]).lower(): k for k, v in researchers_json.items()}


screen_names = set()
for researcher in researchers_json:
    for screen_name in researchers_json[researcher]:
        if screen_name:
            screen_names.add(screen_name)

current_members_path = Path('current_members.json')
current_members = []
current_members_results = []

if not current_members_path.exists():
    #current_members = api.get_list_members(list_id=list_id)
    for member in tweepy.Cursor(api.get_list_members, list_id=list_id).items():
        current_members_results.append(member)
    members_data = [member._json for member in current_members_results]
    current_members_path.write_text(json.dumps(members_data))

current_members = json.loads(current_members_path.read_text())

members_df = pd.json_normalize(current_members)
members_df['cvedata_name'] = members_df['screen_name'].apply(
    lambda x: screen_name_to_researcher_map.get(str(x).lower()))
print(members_df.head())
members_df.to_json('members.json')

current_ids = []
current_screen_names = []

for member in current_members:
    current_ids.append(member['id'])
    current_screen_names.append(member['screen_name'])

print(f"All screen names len {len(screen_names)}")
screen_names_to_add = screen_names.difference(current_screen_names)
screen_names_to_add = list(screen_names_to_add)
print(f"Screen names to add len {len(screen_names_to_add)}")
sub_size = 3

print(f"Need to add {len(screen_names_to_add)} researchers")
print(f"Starting member count = {len(current_screen_names)}")

member_count = len(current_screen_names)
for i in range(0, len(screen_names_to_add), sub_size):
    sub_screen_names = [sn for sn in screen_names_to_add[i: i + sub_size]]

    # rate limit issues https://improveandrepeat.com/2022/03/python-friday-114-debug-tweepy/
    # this section always suffers from Twitter strange rate limiting
    # keep running until satisfied
    try:
        print(f"Adding members: {sub_screen_names}")
        resp = api.add_list_members(
            list_id=list_id, screen_name=sub_screen_names)
        new_member_count = resp.member_count
        print(
            f"Added {new_member_count - member_count} of {len(sub_screen_names)} attempted")
        member_count = new_member_count

        # delete current members as file is not outdated
        if current_members_path.exists():
            current_members_path.unlink()

        time.sleep(1)
    except Exception as e:
        print(f"{e}")
