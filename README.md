# Password Manager 2.0

It has been a long time since my first attempt at a password manager. 
The first time I kept things rather simple storing passwords as plain text.

This manager has a different way for storing passwords, way more secure and safe.

First of all, it uses the bcrypt library for python for hashing master passwords. 
All the other passwords are then encrypted according to the cryptography library. 
The reason I didn't opt for hashing all the passwords is that the process is irreversible, 
and in password managers the ability to retrieve passwords is a key features. 

To increase safety I decided to store the key for decryption in a separate database. 
To encrypt/decrypt a password you need 2 pieces of information: 
- the actual password which is encrypted;
- the key whereby it was encrypted.

This 2 pieces are stored in 2 different databases, which in my opinion increases security 
since one piece is useless without the other. 

### Note for improvement
I decided to give every user ONE key for encryption/decryption. It sounds a bit less secure.
My intention was to generate a key for each password created so that even if someone were able to 
get one key, they would not be able to decrypt all the passwords but just one.
I created the DB to have such a feature in the future (the pwd_id is meant to store the particular
id of a password and in combination with a user_id they'd represent a unique match for the decryption key).

Although, I a not really sure to implement such a feature and if you wanted you could help me in this regard.
If a malevolent user were to access the database and read the key, it wouldn't matter if there were one for each 
user or one for each password, because the hacker would still be able to see them all.

I think that the best solution for now is having the 2 fundamental pieces in 2 separate environments.

Thanks,

@BeGeos