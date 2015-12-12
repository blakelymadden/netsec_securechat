import user, os, json
import local_crypt as LC

PORT_IN = 10001
names = ['Alice', 'Blake', 'Charle', 'Diana', 'Emma',
        'Frank', 'George', 'Haley', 'Isaac', 'Jacob', 'Karen']

def gen_user(uname, pw, port, address="0.0.0.0"):
    usr = user.User(uname, pw, address, port_in=port)
    data = usr.json_dump()
    directory = user.USER_PATH + uname
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(user.User.get_user_data_path(uname), "w") as jsonFile:
        jsonFile.write(json.dumps(data))
    priv_key_path = user.User.get_user_path(uname, "priv_key.pem")
    LC.gen_priv_key(priv_key_path)
    LC.gen_pub_key(user.User.get_user_pub_key_path(uname), priv_key_path)
    

for name in names:
    pw = name[0].lower() + "password"
    gen_user(name, pw, PORT_IN)
    print(name + " " + pw)
    PORT_IN +=1

