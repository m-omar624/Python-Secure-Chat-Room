Introduction to Computer Security
Securing server/client application

This is a secured chat room and file transfer server and application that does the following

-   User authentication
-   Key exchange between the client and server on initialization of the connection.
-   Key exchange between client and client on initialization of a chat session
-   Confidentiality through encryption of client-sever and client-client massages
-   Integrity through use of a MAC appended to all messages (client-server and client-client)
-   Resistance against replay attack

## Usage 

To use the Chat app you first need to run the server. Once the server is running, you run client app to connect to the server. (see instruction below). We assume that both the server and all clients will run locally (i.e., on localhost). 

 Once the client is connected, the user needs to be authenticated with a username and a password.
 
To test the system initially, you can login with one of the ample users: **user1,** **user2**, **user3** 

Password: 123 (for all)

When at least two users have logged in, the program supports the following functionality.

* Sending messages between two users by first "pinging" the user with @user_id and then once a chat connection has established, the user can send one message at a time (this is not very user friendly, but you don't need to worry about the user experience for the assignment purposes)

* Send files using send @userID command. 

* Request a list of users from the server `list` command.

* Echo the server using `echo server` command

* Logout using the `exit' command














