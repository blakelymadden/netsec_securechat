import user, os, json
import local_crypt as LC

PORT_IN = 10001
    
def gen_user(uname, pw, address="0.0.0.0"):
    usr = user.User(uname, pw, address, port_in=PORT_IN)
    PORT_IN += 1
    data = usr.json_dump()
    directory = user.USER_PATH + uname
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(user.User.get_user_data_path(uname), "w") as jsonFile:
        jsonFile.write(json.dumps(data))
    priv_key_path = user.User.get_user_path(uname, "priv_key.pem")
    LC.gen_priv_key(priv_key_path)
    LC.gen_pub_key(user.User.get_user_pub_key_path(uname), priv_key_path)
    

gen_user('Alice', 'apassword')
gen_user('Blake', 'bpassword')
gen_user('Charle', 'cpassword')
gen_user('Diana', 'dpassword')
gen_user('Emma', 'epassword')
gen_user('Frank', 'fpassword')
gen_user('George', 'gpassword')
gen_user('Haley', 'hpassword')
gen_user('Isaac', 'ipassword')
gen_user('Jacob', 'jpassword')
gen_user('Karen', 'kpassword')
