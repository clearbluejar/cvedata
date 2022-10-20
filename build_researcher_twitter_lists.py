import tweepy
import os
import pandas as pd
from pandas import json_normalize
import json

from cvedata.acknowledgements import get_researcher_twitter_map_json

auth = tweepy.OAuthHandler(os.getenv("consumer_key"), os.getenv("consumer_secret"))
auth.set_access_token(os.getenv("access_token"), os.getenv("access_token_secret"))

# rate limit issues https://improveandrepeat.com/2022/03/python-friday-114-debug-tweepy/

api = tweepy.API(auth)
client = tweepy.Client(
    bearer_token=os.getenv("bearer_token"),
    consumer_key=os.getenv("consumer_key"),
    consumer_secret=os.getenv("consumer_secret"),
    access_token=os.getenv("access_token"),
    access_token_secret=os.getenv("access_token_secret"),
    wait_on_rate_limit=True,
)

list_name = "researchers with a CVE"
list_description = "A list of researchers that have earned at least 1 CVE"

# twitter_list = api.create_list(name=list_name, description=list_description, mode='private')
# list_id = twitter_list._json["id"]

list_id = 1582329731005005825
# list_meta = api.get_list(list_id = list_id)

# print("Number of members before add_list_member() is used : " +
#       str(api.get_list(list_id = list_id).member_count))
      

researchers_json = get_researcher_twitter_map_json()

screen_names  = set()
for researcher in researchers_json:
    for screen_name in researchers_json[researcher]:
        if screen_name:
            screen_names.add(screen_name)


current_members = client.get_list_members(list_id,user_auth=True).data

current_ids = []
for member in current_members:
    current_ids.append(member.id)

    # if handle:
    #     print(handle)
    #     try:
    #         user = client.get_user(username=handle, user_auth=True)
        
            
    #         if user.data:
    #             print(user.data['name'])
    #             ids.append(user.data.data['id'])
    #         else:
    #             print(f"{handle} error: {user.errors}")
    #     except Exception as e:
    #         print("Error: {handle} {e}")
    #         continue


# for i in range(0, len(ids), 100):
#     sub_ids = [id for id in ids[i : i + 100]]
#     response = api.add_list_members(list_id=list_id, user_id=sub_ids)
screen_names = list(screen_names)
sub_size = 100

user_dfs = []

# for i in range(0, len(screen_names), sub_size):
#     sub_screen_names = [id for id in screen_names[i : i + sub_size]]
#     response = api.add_list_members(list_id=list_id, screen_name=sub_screen_names, owner_screen_name='clearbluejar', slug=''1582329731005005825')
    
#     print("Number of members after add_list_member() is used : " +
#       str(api.get_list(list_id = list_id).member_count))

users_to_add = []

for i in range(0, len(screen_names), sub_size):
    sub_screen_names = [id for id in screen_names[i : i + sub_size]]
    users = api.lookup_users(screen_name=sub_screen_names)
    print(len(users))
    
    
    for user in users:
        resp = None

        # create dataframe for user
        user_dfs.append(json_normalize(user._json))

        if user.id in current_ids:
            print(f"Skipping {user.name}")
        else:
            print(f"Adding {user.name}")
            users_to_add.append(user)


print(f"Attempting to add {len(users_to_add)} researchers")
for i in range(0, len(users_to_add), sub_size):
    sub_screen_names = [id.screen_name for id in users_to_add[i : i + sub_size]]

    try:
        resp = api.add_list_members(list_id=list_id, screen_name=sub_screen_names)
    except Exception as e:
        print(f"Failed {user.screen_name}")
        print(f"{e}")

        
                #resp = client.add_list_member(id=list_id, user_id=user.id)
            #resp = api.add_list_member(list_id=list_id,id=user.id)
            
            # try:
            #     #resp = api.add_list_member(list_id=list_id,screen_name=user.screen_name)
            #     resp = client.add_list_member(id=list_id,user_id=user.id)
            # except Exception as e:
            #     print(f"Failed {user.screen_name}")
            #     print(f"{e}")



df = pd.concat(user_dfs,ignore_index=True)
print(df.head(10))
df.to_markdown('users.md')
df.to_json('user.json')





    #print(f"Add member succeeded: {response}")
    # print("Number of members before add_list_member() is used : " +
    #   str(api.get_list(list_id = list_id).member_count))

print("done")