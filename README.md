#Secure Chat 

###System Requirments
- python 3.0 or higher
- python [cryptography](https://cryptography.io/en/latest/) library 


###Running
To run the ChatServer use *python ChatServer.py -sp PORT*, where PORT is a given port number. 
<br/>
To run the ChatClient use *python ChatClient.py -sip IP -sp PORT*, where IP is a given IP address and PORT is a given port number. The client port number should match the server port number.
<br/><br/>
One the client side a user has 2 opetions:
1. list: lists all the current active users
2. send USER MESSAGE: sends the user of name USER the contents of MESSAGE as long as that user is currently active

###User set up
Users are set up in the same folder as ChatServer.py. A user's folder contains a json formated text file that is fomatted NAME_data.txt and a public key pem file formatted as NAME_pub_key.pem, where NAME is the user's log-in name. Below is an example of the user file tree.

    users file path
        |
        -/users
            |
            - /al
            |
            - - al_data.txt
            - - al_pub_key.pem
            ...
            ...
            - /zoe
            |
            - - zoe_data.txt
            - - zoe_pub_key.pem
            
    user NAME_data.txt example
    {   
        "name": "al", 
        "password": PASSWORD_HASH,
        "addresss": "0.0.0.0", 
        "port_in": 10001,
    }
            