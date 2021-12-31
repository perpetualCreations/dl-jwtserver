"""Test cases for users."""

import requests

# create user.
cu_request = requests.put("http://127.0.0.1:5000/claims/alice",
                          json={"email": "alice@dreamerslegacy.xyz",
                                "password": "hunter2"})
print(cu_request.status_code)
print(cu_request.json())
print("===")

# create user that already exists.
cue_request = requests.put("http://127.0.0.1:5000/claims/alice",
                           json={"email": "alice@dreamerslegacy.xyz",
                                 "password": "hunter2"})
print(cue_request.status_code)
print(cue_request.json())
print("===")

# get auth JWT for user.
ug_request = requests.get("http://127.0.0.1:5000/claims/alice",
                          json={"answer": "hunter2",
                                "mode": "password"})
print(ug_request.status_code)
print(ug_request.json())
print("===")

# try to get auth JWT for user, however with invalid password.
ugi_request = requests.get("http://127.0.0.1:5000/claims/alice",
                           json={"answer": "password",
                                 "mode": "password"})
print(ugi_request.status_code)
print(ugi_request.json())
print("===")

# try to get auth JWT for user, however with no additional parameters.
ugm_request = requests.get("http://127.0.0.1:5000/claims/alice")
print(ugm_request.status_code)
print(ugm_request.json())
print("===")

# update user email and password with incorrect types.
upt_request = requests.patch("http://127.0.0.1:5000/claims/alice",
                             json={"new": {
                                 "email": "alice@example.com",
                                 "password": 0},
                                   "answer": "hunter2",
                                   "mode": "password"})
print(upt_request.status_code)
print(upt_request.json())
print("===")

# update user email and password.
up_request = requests.patch("http://127.0.0.1:5000/claims/alice",
                            json={"new": {
                                "email": "alice@example.com",
                                "password": "l33tsp34k"},
                                  "answer": "hunter2",
                                  "mode": "password"})
print(up_request.status_code)
print(up_request.json())
print("===")

# test password again.
ugap_request = requests.get("http://127.0.0.1:5000/claims/alice",
                            json={"answer": "l33tsp34k",
                                  "mode": "password"})
print(ugap_request.status_code)
print(ugap_request.json())
print("===")

# delete user.
ud_request = requests.delete("http://127.0.0.1:5000/claims/alice",
                             json={"answer": "l33tsp34k",
                                   "mode": "password"})
print(ud_request.status_code)
print(ud_request.json())
print("===")

# create user with no email.
cune_request = requests.put("http://127.0.0.1:5000/claims/bob",
                            json={"password": "1234567890"})
print(cune_request.status_code)
print(cune_request.json())
print("===")

# get auth JWT for user with no email.
ugne_request = requests.get("http://127.0.0.1:5000/claims/bob",
                            json={"answer": "1234567890",
                                  "mode": "password"})
print(ug_request.status_code)
print(ug_request.json())
print("===")

# delete user with no email.
udne_request = requests.delete("http://127.0.0.1:5000/claims/bob",
                               json={"answer": "1234567890",
                                     "mode": "password"})
print(udne_request.status_code)
print(udne_request.json())
print("===")
