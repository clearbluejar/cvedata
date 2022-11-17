import os
import json
from pathlib import Path
import time
from datetime import datetime

import tweepy
import pandas as pd
from cvedata.acknowledgements import get_researcher_twitter_map_json

BASE_DIR = Path(__file__).parent

# Setup twitter client

# set tokens
import auth_tweepy

auth = tweepy.OAuthHandler(os.getenv("consumer_key"),os.getenv("consumer_secret"))
auth.set_access_token(os.getenv("access_token"),os.getenv("access_token_secret"))

api = tweepy.API(auth, wait_on_rate_limit=True)

# didn't have great success using API v2
# client = tweepy.Client(
#     bearer_token=os.getenv("bearer_token"),
#     consumer_key=os.getenv("consumer_key"),
#     consumer_secret=os.getenv("consumer_secret"),
#     access_token=os.getenv("access_token"),
#     access_token_secret=os.getenv("access_token_secret"),
#     wait_on_rate_limit=True,
# )

# Used to create list

# list_name = "researchers with a CVE"
# list_description = "A list of researchers that have earned at least 1 CVE"

# twitter_list = api.create_list(name=list_name, description=list_description, mode='private')
# list_id = twitter_list._json["id"]

list_id = 1582329731005005825
list_id = 1593117039949905921

researchers_json = get_researcher_twitter_map_json()
screen_name_to_researcher_map = {
    str(v[0]).lower(): k for k, v in researchers_json.items()}

screen_names = set()
for researcher in researchers_json:
    for screen_name in researchers_json[researcher]:
        if screen_name:
            screen_names.add(screen_name)

current_members_path = Path(BASE_DIR, 'current_members.json')
current_members = []
current_members_results = []

if not current_members_path.exists():
    #current_members = api.get_list_members(list_id=list_id)
    for member in tweepy.Cursor(api.get_list_members, list_id=list_id).items():
        current_members_results.append(member)
    members_data = [member._json for member in current_members_results]
    current_members_path.write_text(json.dumps(members_data))

current_members = json.loads(current_members_path.read_text())

if len(current_members) > 0:
    # Save dataframe of current list members
    members_df = pd.json_normalize(current_members)

    # Map back to names from original list
    members_df['cvedata_name'] = members_df['screen_name'].apply(
        lambda x: screen_name_to_researcher_map.get(str(x).lower()))

    members_df.to_json(BASE_DIR / 'members.json')
    print(members_df.head())

current_ids = []
current_screen_names = []

for member in current_members:
    current_ids.append(member['id'])
    current_screen_names.append(member['screen_name'])

print(f"All screen names len {len(screen_names)}")
screen_names_to_add = screen_names.difference(current_screen_names)
screen_names_to_add = list(screen_names_to_add)
print(f"Screen names to add len {len(screen_names_to_add)}")

# check validity of names
valid_screen_names = []
sub_size = 100

invalid_sn_path = Path(BASE_DIR,'invalid_screen_names.json')

if invalid_sn_path.exists() and datetime.fromtimestamp(invalid_sn_path.stat().st_mtime).day == datetime.now().day:
    # load cached version
    invalid_sn = json.loads(invalid_sn_path.read_text())
else:
    # check names again
    for i in range(0, len(screen_names_to_add), sub_size):
        sub_screen_names = [sn for sn in screen_names_to_add[i: i + sub_size]]
        users = api.lookup_users(screen_name=sub_screen_names)
        
        for user in users:            
            if user.screen_name and not user.protected:
                valid_screen_names.append(user.screen_name.lower())

    invalid_sn = set(screen_names_to_add).difference(set(valid_screen_names))
    invalid_sn = list(invalid_sn)
    invalid_sn_path.write_text(json.dumps(invalid_sn))



print(f"Invalid Screennames {len(invalid_sn)}")

# remove invalid screen names (suspended, doesn't exist, etc..)
screen_names_to_add = list(set(screen_names_to_add).difference(set(invalid_sn)))

print(f"Need to add {len(screen_names_to_add)} valid researchers")
print(f"Starting member count = {len(current_screen_names)}")

sub_size = 10 # twitter doesn't like you to add 100 at once
member_count = len(current_screen_names)
for i in range(0, len(screen_names_to_add), sub_size):
    sub_screen_names = [sn for sn in screen_names_to_add[i: i + sub_size]]

    # rate limit issues https://improveandrepeat.com/2022/03/python-friday-114-debug-tweepy/
    # this section always suffers from Twitter strange rate limiting
    # keep running until satisfied
    try:
        time.sleep(2)
        print(f"Adding members: {sub_screen_names}")
        resp = api.add_list_members(
            list_id=list_id, screen_name=sub_screen_names)
        # resp = api.add_list_member(
        #     list_id=list_id, screen_name=sub_screen_names[0])
        new_member_count = resp.member_count
        added = new_member_count - member_count
        print(
            f"Added {added} of {len(sub_screen_names)} attempted")
        member_count = new_member_count

        # delete current members as file is not outdated
        if current_members_path.exists() and added > 0:
            current_members_path.unlink()
            invalid_sn_path.unlink()


    except Exception as e:
        print(f"{e}")
